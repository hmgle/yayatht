use crate::config::LaunchConfig;
use crate::control;
use crate::instance::Instance;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use yayatht_sys::clone::{CloneResult, clone_namespaced};
use yayatht_sys::control::Kind;
use yayatht_sys::process::WaitStatus;

const COMMON_NAMESPACES: u64 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWPID) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitStatus {
    pub code: i32,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("system operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("data plane failed during startup: {0}")]
    Dataplane(String),
    #[error("namespace init failed during startup: {0}")]
    Namespace(String),
}

pub struct Supervisor;

impl Supervisor {
    pub fn run(mut config: LaunchConfig) -> Result<ExitStatus, Error> {
        config.validate()?;
        let dataplane_fd_limit =
            yayatht_sys::resource::dataplane_nofile_limit(config.max_tcp_flows)?;
        yayatht_sys::resource::ensure_nofile_capacity(dataplane_fd_limit)?;
        yayatht_sys::caps::set_child_subreaper()?;
        let signal_fd = yayatht_sys::signal::SignalFd::block(&[
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGCHLD,
        ])?;
        let mut instance =
            Instance::create(config.name.as_deref(), config.runtime_root.as_deref())?;
        info!(instance = %instance.metadata().instance_id, runtime = %instance.directory.display(), "starting instance");

        let (dp_parent, dp_child) = yayatht_sys::fdpass::seqpacket_pair()?;
        let (ns_parent, ns_child) = yayatht_sys::fdpass::seqpacket_pair()?;
        let (tap_dp, tap_ns) = yayatht_sys::fdpass::seqpacket_pair()?;

        let dataplane_config = config.network.dataplane(
            &config.upstream,
            config.max_tcp_flows,
            config.max_pending_tcp_bytes,
            config.max_retained_tcp_bytes,
            config.tcp_receive_buffer_bytes,
            config.tcp_send_buffer_bytes,
        );
        let (dataplane_pid, dataplane_pidfd) = match clone_namespaced(COMMON_NAMESPACES)? {
            CloneResult::Child => {
                drop(signal_fd);
                drop(dp_parent);
                drop(ns_parent);
                drop(ns_child);
                drop(tap_ns);
                data_plane_child(dp_child, tap_dp, dataplane_config);
            }
            CloneResult::Parent { pid, pidfd } => (pid, pidfd),
        };
        drop(dataplane_config);
        config.clear_proxy_credentials();

        let (namespace_pid, namespace_pidfd) =
            match clone_namespaced(COMMON_NAMESPACES | libc::CLONE_NEWNET as u64) {
                Ok(CloneResult::Child) => {
                    drop(signal_fd);
                    drop(ns_parent);
                    drop(dp_parent);
                    drop(dp_child);
                    drop(tap_dp);
                    namespace_child(ns_child, tap_ns, config);
                }
                Ok(CloneResult::Parent { pid, pidfd }) => (pid, pidfd),
                Err(error) => {
                    let _ = yayatht_sys::clone::pidfd_send_signal(
                        dataplane_pidfd.as_raw_fd(),
                        libc::SIGKILL,
                    );
                    let _ = yayatht_sys::process::wait_pid(dataplane_pid, false);
                    return Err(error.into());
                }
            };
        let mut child_guard = ChildGuard::new(
            dataplane_pid,
            dataplane_pidfd.as_raw_fd(),
            namespace_pid,
            namespace_pidfd.as_raw_fd(),
        );

        drop(dp_child);
        drop(ns_child);
        drop(tap_dp);
        drop(tap_ns);

        if let Err(error) = write_identity_maps(dataplane_pid) {
            kill_children(
                &dataplane_pidfd,
                &namespace_pidfd,
                dataplane_pid,
                namespace_pid,
            );
            return Err(error.into());
        }
        if let Err(error) = write_identity_maps(namespace_pid) {
            kill_children(
                &dataplane_pidfd,
                &namespace_pidfd,
                dataplane_pid,
                namespace_pid,
            );
            return Err(error.into());
        }
        control::send(dp_parent.as_raw_fd(), Kind::MapsReady, 1, &[])?;
        control::send(ns_parent.as_raw_fd(), Kind::MapsReady, 1, &[])?;

        if let Err(error) = expect_ready(ns_parent.as_raw_fd(), "namespace") {
            kill_children(
                &dataplane_pidfd,
                &namespace_pidfd,
                dataplane_pid,
                namespace_pid,
            );
            return Err(error);
        }
        if let Err(error) = expect_ready(dp_parent.as_raw_fd(), "data plane") {
            kill_children(
                &dataplane_pidfd,
                &namespace_pidfd,
                dataplane_pid,
                namespace_pid,
            );
            return Err(error);
        }

        instance.update_children(dataplane_pid, namespace_pid)?;
        control::send(ns_parent.as_raw_fd(), Kind::Exec, 2, &[])?;
        let target_payload = control::expect(ns_parent.as_raw_fd(), Kind::Status)?;
        if target_payload.len() != 4 {
            kill_children(
                &dataplane_pidfd,
                &namespace_pidfd,
                dataplane_pid,
                namespace_pid,
            );
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid target pid").into());
        }
        let target_pid = i32::from_le_bytes(target_payload.try_into().expect("target pid length"));
        instance.set_target(target_pid)?;
        info!(target_pid, "target command started");

        yayatht_sys::set_nonblocking(ns_parent.as_raw_fd(), true)?;
        yayatht_sys::set_nonblocking(dp_parent.as_raw_fd(), true)?;
        let exit_code = supervise_running(
            &mut instance,
            &signal_fd,
            &ns_parent,
            &dp_parent,
            namespace_pid,
            &namespace_pidfd,
            dataplane_pid,
            &dataplane_pidfd,
        )?;
        child_guard.disarm();
        instance.set_state("exited")?;
        Ok(ExitStatus { code: exit_code })
    }
}

fn expect_ready(fd: i32, role: &str) -> Result<(), Error> {
    let mut buffer = vec![0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
    let message = control::receive(fd, &mut buffer)?;
    match message.kind {
        Kind::Ready => Ok(()),
        Kind::Error if role == "namespace" => Err(Error::Namespace(
            String::from_utf8_lossy(message.payload).into_owned(),
        )),
        Kind::Error => Err(Error::Dataplane(
            String::from_utf8_lossy(message.payload).into_owned(),
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected {role} message: {other:?}"),
        )
        .into()),
    }
}

fn data_plane_child(
    control_fd: OwnedFd,
    tap_channel: OwnedFd,
    config: yayatht_dataplane::reactor::Config,
) -> ! {
    let error_control = rustix::io::dup(&control_fd).ok();
    let result = (|| -> Result<(), io::Error> {
        yayatht_sys::caps::set_parent_death_signal(libc::SIGKILL)?;
        control::expect(control_fd.as_raw_fd(), Kind::MapsReady)?;
        let mut payload = [0u8; 128];
        let (length, tap) = yayatht_sys::fdpass::recv_fd(tap_channel.as_raw_fd(), &mut payload)?;
        let message = yayatht_sys::control::decode(&payload[..length])?;
        if message.kind != Kind::Ready {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TAP transfer",
            ));
        }
        drop(tap_channel);
        let nofile_limit = yayatht_sys::resource::dataplane_nofile_limit(config.max_tcp_flows)?;
        yayatht_sys::resource::set_nofile_limit(nofile_limit)?;
        yayatht_sys::caps::drop_all_capabilities()?;
        yayatht_sys::caps::set_no_new_privs()?;
        control::send(control_fd.as_raw_fd(), Kind::Ready, 1, &[])?;
        yayatht_sys::set_nonblocking(control_fd.as_raw_fd(), true)?;
        let metrics = yayatht_dataplane::reactor::run(config, tap, control_fd)
            .map_err(|error| io::Error::other(error.to_string()))?;
        debug!(?metrics, "data plane stopped");
        Ok(())
    })();
    match result {
        Ok(()) => yayatht_sys::clone::exit_immediately(0),
        Err(error) => {
            if let Some(error_control) = error_control {
                let _ = control::send(
                    error_control.as_raw_fd(),
                    Kind::Error,
                    0,
                    error.to_string().as_bytes(),
                );
            }
            error!(%error, "data-plane child failed");
            yayatht_sys::clone::exit_immediately(125);
        }
    }
}

fn namespace_child(control_fd: OwnedFd, tap_channel: OwnedFd, config: LaunchConfig) -> ! {
    let result = namespace_child_inner(&control_fd, &tap_channel, &config);
    match result {
        Ok(code) => {
            let _ = control::send(control_fd.as_raw_fd(), Kind::Exit, 3, &code.to_le_bytes());
            yayatht_sys::clone::exit_immediately(0);
        }
        Err(error) => {
            let _ = control::send(
                control_fd.as_raw_fd(),
                Kind::Error,
                0,
                error.to_string().as_bytes(),
            );
            error!(%error, "namespace child failed");
            yayatht_sys::clone::exit_immediately(125);
        }
    }
}

fn namespace_child_inner(
    control_fd: &OwnedFd,
    tap_channel: &OwnedFd,
    config: &LaunchConfig,
) -> io::Result<i32> {
    yayatht_sys::caps::set_parent_death_signal(libc::SIGKILL)?;
    control::expect(control_fd.as_raw_fd(), Kind::MapsReady)?;
    yayatht_sys::mount::mount_private_proc()?;
    debug_failpoint("ns_tap")?;
    let tap = yayatht_sys::tun::create_tap(&config.network.interface_name)?;
    yayatht_sys::netlink::configure_namespace(
        &config.network.interface_name,
        config.network.target_mac.octets(),
        config
            .network
            .target_ipv4
            .zip(config.network.gateway_ipv4)
            .map(|((address, prefix), gateway)| (address, prefix, gateway)),
        config
            .network
            .target_ipv6
            .zip(config.network.gateway_ipv6)
            .map(|((address, prefix), gateway)| (address, prefix, gateway)),
    )?;
    let message = yayatht_sys::control::encode(Kind::Ready, 1, &[])?;
    yayatht_sys::fdpass::send_fd(tap_channel.as_raw_fd(), tap.as_raw_fd(), &message)?;
    drop(tap);
    control::send(control_fd.as_raw_fd(), Kind::Ready, 1, &[])?;
    control::expect(control_fd.as_raw_fd(), Kind::Exec)?;

    let command = config
        .command
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command contains an embedded NUL",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let target_pid = yayatht_sys::process::fork_exec(&command)?;
    control::send(
        control_fd.as_raw_fd(),
        Kind::Status,
        2,
        &target_pid.to_le_bytes(),
    )?;
    yayatht_sys::set_nonblocking(control_fd.as_raw_fd(), true)?;
    let signals = yayatht_sys::signal::SignalFd::block(&[
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGCHLD,
    ])?;
    let mut main_status = None;
    loop {
        while let Some(signal) = signals.read()? {
            if signal != libc::SIGCHLD {
                yayatht_sys::process::signal_process_group(target_pid, signal)?;
            }
        }
        let mut control_buffer = [0u8; 128];
        match control::receive(control_fd.as_raw_fd(), &mut control_buffer) {
            Ok(message) if message.kind == Kind::Shutdown => {
                yayatht_sys::process::signal_process_group(target_pid, libc::SIGTERM)?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                yayatht_sys::process::signal_process_group(target_pid, libc::SIGTERM)?;
            }
            Err(error) => return Err(error),
        }
        loop {
            match yayatht_sys::process::wait_any_nohang()? {
                Some((-1, WaitStatus::StillRunning)) => break,
                Some((pid, WaitStatus::Exited(code))) => {
                    if pid == target_pid {
                        main_status = Some(code);
                    }
                }
                Some((pid, WaitStatus::Signaled(signal))) => {
                    if pid == target_pid {
                        main_status = Some(128 + signal);
                    }
                }
                Some((_pid, WaitStatus::StillRunning)) => {}
                Some((_, WaitStatus::NoChildren)) | None => {
                    if let Some(code) = main_status {
                        return Ok(code);
                    }
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[allow(clippy::too_many_arguments)]
fn supervise_running(
    instance: &mut Instance,
    signals: &yayatht_sys::signal::SignalFd,
    ns_control: &OwnedFd,
    dp_control: &OwnedFd,
    namespace_pid: i32,
    namespace_pidfd: &OwnedFd,
    dataplane_pid: i32,
    dataplane_pidfd: &OwnedFd,
) -> Result<i32, Error> {
    loop {
        while let Some(signal) = signals.read()? {
            if signal != libc::SIGCHLD {
                yayatht_sys::clone::pidfd_send_signal(namespace_pidfd.as_raw_fd(), signal)?;
            }
        }
        serve_status(instance, dp_control)?;
        let mut buffer = vec![0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
        match control::receive(ns_control.as_raw_fd(), &mut buffer) {
            Ok(message) if message.kind == Kind::Exit => {
                if message.payload.len() != 4 {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidData, "invalid exit status").into(),
                    );
                }
                let code =
                    i32::from_le_bytes(message.payload.try_into().expect("exit status length"));
                let shutdown = yayatht_sys::control::encode(Kind::Shutdown, 3, &[])?;
                let _ = yayatht_sys::fdpass::send_packet(dp_control.as_raw_fd(), &shutdown);
                let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
                let _ = yayatht_sys::process::wait_pid(dataplane_pid, false);
                return Ok(code);
            }
            Ok(message) if message.kind == Kind::Error => {
                return Err(Error::Namespace(
                    String::from_utf8_lossy(message.payload).into_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::Namespace("control channel closed".to_owned()));
            }
            Err(error) => return Err(error.into()),
        }
        match yayatht_sys::process::wait_pid(dataplane_pid, true)? {
            WaitStatus::StillRunning => {}
            status => {
                warn!(?status, "data plane exited before target");
                let _ = yayatht_sys::clone::pidfd_send_signal(
                    namespace_pidfd.as_raw_fd(),
                    libc::SIGTERM,
                );
                let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
                return Err(Error::Dataplane("exited before target command".to_owned()));
            }
        }
        match yayatht_sys::process::wait_pid(namespace_pid, true)? {
            WaitStatus::StillRunning => {}
            status => {
                warn!(?status, "namespace init exited without status message");
                let shutdown = yayatht_sys::control::encode(Kind::Shutdown, 3, &[])?;
                let _ = yayatht_sys::fdpass::send_packet(dp_control.as_raw_fd(), &shutdown);
                let _ = yayatht_sys::process::wait_pid(dataplane_pid, false);
                return Err(Error::Namespace("exited without target status".to_owned()));
            }
        }
        let _ = dataplane_pidfd;
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn serve_status(instance: &Instance, dataplane_control: &OwnedFd) -> io::Result<()> {
    loop {
        let (mut stream, _) = match instance.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        };
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut request = [0u8; 128];
        let length = stream.read(&mut request)?;
        let message = yayatht_sys::control::decode(&request[..length])?;
        if message.kind != Kind::Status {
            continue;
        }
        let mut payload: serde_json::Value =
            serde_json::from_slice(&instance.metadata_json()?).map_err(io::Error::other)?;
        let metrics = query_dataplane_metrics(dataplane_control)?;
        payload
            .as_object_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid instance JSON"))?
            .insert("dataplane".to_owned(), metrics);
        let payload = serde_json::to_vec_pretty(&payload).map_err(io::Error::other)?;
        let response = yayatht_sys::control::encode(Kind::Status, message.request_id, &payload)?;
        stream.write_all(&response)?;
    }
    Ok(())
}

fn query_dataplane_metrics(control_fd: &OwnedFd) -> io::Result<serde_json::Value> {
    const REQUEST_ID: u64 = 0x6d65_7472_6963_7301;
    control::send(control_fd.as_raw_fd(), Kind::Status, REQUEST_ID, &[])?;
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut buffer = vec![0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
    loop {
        match control::receive(control_fd.as_raw_fd(), &mut buffer) {
            Ok(message) if message.kind == Kind::Status && message.request_id == REQUEST_ID => {
                return serde_json::from_slice(message.payload).map_err(io::Error::other);
            }
            Ok(message) if message.kind == Kind::Error => {
                return Err(io::Error::other(
                    String::from_utf8_lossy(message.payload).into_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out querying data-plane metrics",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn write_identity_maps(pid: i32) -> io::Result<()> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let root = Path::new("/proc").join(pid.to_string());
    match fs::write(root.join("setgroups"), b"deny") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::write(root.join("uid_map"), format!("0 {uid} 1\n"))?;
    fs::write(root.join("gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}

fn kill_children(
    dataplane_pidfd: &OwnedFd,
    namespace_pidfd: &OwnedFd,
    dataplane_pid: i32,
    namespace_pid: i32,
) {
    let _ = yayatht_sys::clone::pidfd_send_signal(dataplane_pidfd.as_raw_fd(), libc::SIGKILL);
    let _ = yayatht_sys::clone::pidfd_send_signal(namespace_pidfd.as_raw_fd(), libc::SIGKILL);
    let _ = yayatht_sys::process::wait_pid(dataplane_pid, false);
    let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
}

struct ChildGuard {
    dataplane_pid: i32,
    dataplane_pidfd: i32,
    namespace_pid: i32,
    namespace_pidfd: i32,
    armed: bool,
}

impl ChildGuard {
    const fn new(
        dataplane_pid: i32,
        dataplane_pidfd: i32,
        namespace_pid: i32,
        namespace_pidfd: i32,
    ) -> Self {
        Self {
            dataplane_pid,
            dataplane_pidfd,
            namespace_pid,
            namespace_pidfd,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = yayatht_sys::clone::pidfd_send_signal(self.dataplane_pidfd, libc::SIGKILL);
        let _ = yayatht_sys::clone::pidfd_send_signal(self.namespace_pidfd, libc::SIGKILL);
        let _ = yayatht_sys::process::wait_pid(self.dataplane_pid, false);
        let _ = yayatht_sys::process::wait_pid(self.namespace_pid, false);
    }
}

fn debug_failpoint(name: &str) -> io::Result<()> {
    if cfg!(debug_assertions)
        && std::env::var_os("YAYATHT_TEST_FAIL_AT").is_some_and(|value| value == name)
    {
        return Err(io::Error::other(format!("injected failure at {name}")));
    }
    Ok(())
}
