use crate::config::{DnsMode, LaunchConfig, NetworkConfig, SandboxConfig};
use crate::control;
use crate::instance::Instance;
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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

struct DataPlaneWorker {
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
}

impl Supervisor {
    pub fn run(mut config: LaunchConfig) -> Result<ExitStatus, Error> {
        config.validate()?;
        let dataplane_fd_limit = (0..config.workers)
            .map(|worker_index| {
                let worker = config.dataplane(worker_index);
                yayatht_sys::resource::dataplane_nofile_limit(
                    worker.max_tcp_flows,
                    worker.max_udp_flows,
                    worker.max_udp_associations,
                )
            })
            .collect::<io::Result<Vec<_>>>()?
            .into_iter()
            .max()
            .expect("configuration has at least one worker");
        let supervisor_fd_limit = u64::try_from(config.workers)
            .unwrap_or(u64::MAX)
            .saturating_mul(4)
            .saturating_add(32);
        yayatht_sys::resource::ensure_nofile_capacity(dataplane_fd_limit.max(supervisor_fd_limit))?;
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

        let (ns_parent, ns_child) = yayatht_sys::fdpass::seqpacket_pair()?;

        let resolv_conf = if config.dns.mode != DnsMode::Off {
            Some(instance.write_resolv_conf(&gateway_resolv_conf(&config.network))?)
        } else {
            None
        };
        let sandbox = config.sandbox;
        if !sandbox.enabled() {
            warn!(
                "data-plane sandbox disabled: seccomp, filesystem isolation, and core-dump clamp are off"
            );
        }
        let mut workers = Vec::with_capacity(config.workers);
        let mut tap_channels = Vec::with_capacity(config.workers);
        for worker_index in 0..config.workers {
            let (dp_parent, dp_child) = match yayatht_sys::fdpass::seqpacket_pair() {
                Ok(pair) => pair,
                Err(error) => {
                    kill_dataplanes(&workers);
                    return Err(error.into());
                }
            };
            let (tap_dp, tap_ns) = match yayatht_sys::fdpass::seqpacket_pair() {
                Ok(pair) => pair,
                Err(error) => {
                    kill_dataplanes(&workers);
                    return Err(error.into());
                }
            };
            let dataplane_config = config.dataplane(worker_index);
            match clone_namespaced(COMMON_NAMESPACES) {
                Ok(CloneResult::Child) => {
                    drop(signal_fd);
                    drop(ns_parent);
                    drop(ns_child);
                    drop(dp_parent);
                    drop(tap_ns);
                    drop(workers);
                    drop(tap_channels);
                    data_plane_child(dp_child, tap_dp, sandbox, dataplane_config);
                }
                Ok(CloneResult::Parent { pid, pidfd }) => {
                    drop(dp_child);
                    drop(tap_dp);
                    workers.push(DataPlaneWorker {
                        pid,
                        pidfd,
                        control: dp_parent,
                    });
                    tap_channels.push(tap_ns);
                }
                Err(error) => {
                    kill_dataplanes(&workers);
                    return Err(error.into());
                }
            }
        }
        config.clear_proxy_credentials();

        let (namespace_pid, namespace_pidfd) =
            match clone_namespaced(COMMON_NAMESPACES | libc::CLONE_NEWNET as u64) {
                Ok(CloneResult::Child) => {
                    drop(signal_fd);
                    drop(ns_parent);
                    drop(workers);
                    namespace_child(ns_child, tap_channels, config, resolv_conf);
                }
                Ok(CloneResult::Parent { pid, pidfd }) => (pid, pidfd),
                Err(error) => {
                    kill_dataplanes(&workers);
                    return Err(error.into());
                }
            };
        let mut child_guard = ChildGuard::new(&workers, namespace_pid, &namespace_pidfd);

        drop(ns_child);
        drop(tap_channels);

        for worker in &workers {
            if let Err(error) = write_identity_maps(worker.pid) {
                kill_children(&workers, &namespace_pidfd, namespace_pid);
                return Err(error.into());
            }
        }
        if let Err(error) = write_identity_maps(namespace_pid) {
            kill_children(&workers, &namespace_pidfd, namespace_pid);
            return Err(error.into());
        }
        for worker in &workers {
            control::send(worker.control.as_raw_fd(), Kind::MapsReady, 1, &[])?;
        }
        control::send(ns_parent.as_raw_fd(), Kind::MapsReady, 1, &[])?;

        if let Err(error) = expect_ready(ns_parent.as_raw_fd(), "namespace") {
            kill_children(&workers, &namespace_pidfd, namespace_pid);
            return Err(error);
        }
        for (worker_index, worker) in workers.iter().enumerate() {
            if let Err(error) = expect_ready(worker.control.as_raw_fd(), "data plane") {
                warn!(worker_index, "data-plane worker failed during startup");
                kill_children(&workers, &namespace_pidfd, namespace_pid);
                return Err(error);
            }
        }

        let worker_pids = workers.iter().map(|worker| worker.pid).collect::<Vec<_>>();
        instance.update_children(&worker_pids, namespace_pid)?;
        control::send(ns_parent.as_raw_fd(), Kind::Exec, 2, &[])?;
        let target_payload = control::expect(ns_parent.as_raw_fd(), Kind::Status)?;
        if target_payload.len() != 4 {
            kill_children(&workers, &namespace_pidfd, namespace_pid);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid target pid").into());
        }
        let target_pid = i32::from_le_bytes(target_payload.try_into().expect("target pid length"));
        instance.set_target(target_pid)?;
        info!(target_pid, "target command started");

        yayatht_sys::set_nonblocking(ns_parent.as_raw_fd(), true)?;
        for worker in &workers {
            yayatht_sys::set_nonblocking(worker.control.as_raw_fd(), true)?;
        }
        let exit_code = supervise_running(
            &mut instance,
            &signal_fd,
            &ns_parent,
            &workers,
            namespace_pid,
            &namespace_pidfd,
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
    sandbox: SandboxConfig,
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
        let forbidden_syscall_failpoint = cfg!(debug_assertions)
            && std::env::var_os("YAYATHT_TEST_FAIL_AT")
                .is_some_and(|value| value == "dp_forbidden_syscall");
        let nofile_limit = yayatht_sys::resource::dataplane_nofile_limit(
            config.max_tcp_flows,
            config.max_udp_flows,
            config.max_udp_associations,
        )?;
        yayatht_sys::resource::set_nofile_limit(nofile_limit)?;
        if sandbox.enabled() {
            yayatht_sys::resource::disable_core_dumps()?;
            yayatht_sys::mount::isolate_filesystem()?;
        }
        yayatht_sys::caps::drop_all_capabilities()?;
        yayatht_sys::caps::set_no_new_privs()?;
        if sandbox.enabled() {
            yayatht_sys::seccomp::install(yayatht_sys::seccomp::Profile::DataPlane)?;
        }
        if forbidden_syscall_failpoint {
            // Deliberately absent from the data-plane profile. This is kept
            // behind a debug-only failpoint for the rootless negative test.
            let _ = rustix::process::getpid();
            return Err(io::Error::other("forbidden syscall was not blocked"));
        }
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

fn namespace_child(
    control_fd: OwnedFd,
    tap_channels: Vec<OwnedFd>,
    config: LaunchConfig,
    resolv_conf: Option<PathBuf>,
) -> ! {
    let result = namespace_child_inner(&control_fd, &tap_channels, &config, resolv_conf.as_deref());
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
    tap_channels: &[OwnedFd],
    config: &LaunchConfig,
    resolv_conf: Option<&Path>,
) -> io::Result<i32> {
    yayatht_sys::caps::set_parent_death_signal(libc::SIGKILL)?;
    control::expect(control_fd.as_raw_fd(), Kind::MapsReady)?;
    yayatht_sys::mount::mount_private_proc()?;
    if let Some(source) = resolv_conf {
        yayatht_sys::mount::bind_resolv_conf(source)?;
    }
    debug_failpoint("ns_tap")?;
    let multi_queue = tap_channels.len() > 1;
    let taps = tap_channels
        .iter()
        .map(|_| {
            yayatht_sys::tun::create_tap(
                &config.network.interface_name,
                config.network.tap_offload,
                multi_queue,
            )
        })
        .collect::<io::Result<Vec<_>>>()?;
    yayatht_sys::netlink::configure_namespace(
        &config.network.interface_name,
        config.network.target_mac.octets(),
        config.network.tap_mtu,
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
    for (channel, tap) in tap_channels.iter().zip(&taps) {
        yayatht_sys::fdpass::send_fd(channel.as_raw_fd(), tap.as_raw_fd(), &message)?;
    }
    drop(taps);
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
    workers: &[DataPlaneWorker],
    namespace_pid: i32,
    namespace_pidfd: &OwnedFd,
) -> Result<i32, Error> {
    loop {
        while let Some(signal) = signals.read()? {
            if signal != libc::SIGCHLD {
                yayatht_sys::clone::pidfd_send_signal(namespace_pidfd.as_raw_fd(), signal)?;
            }
        }
        serve_status(instance, workers)?;
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
                shutdown_dataplanes(workers);
                let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
                wait_dataplanes(workers);
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
        for (worker_index, worker) in workers.iter().enumerate() {
            match yayatht_sys::process::wait_pid(worker.pid, true)? {
                WaitStatus::StillRunning => {}
                status => {
                    warn!(
                        worker_index,
                        ?status,
                        "data-plane worker exited before target"
                    );
                    shutdown_dataplanes(workers);
                    let _ = yayatht_sys::clone::pidfd_send_signal(
                        namespace_pidfd.as_raw_fd(),
                        libc::SIGTERM,
                    );
                    let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
                    wait_dataplanes(workers);
                    return Err(Error::Dataplane(format!(
                        "worker {worker_index} exited before target command"
                    )));
                }
            }
        }
        match yayatht_sys::process::wait_pid(namespace_pid, true)? {
            WaitStatus::StillRunning => {}
            status => {
                warn!(?status, "namespace init exited without status message");
                shutdown_dataplanes(workers);
                wait_dataplanes(workers);
                return Err(Error::Namespace("exited without target status".to_owned()));
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn shutdown_dataplanes(workers: &[DataPlaneWorker]) {
    let Ok(shutdown) = yayatht_sys::control::encode(Kind::Shutdown, 3, &[]) else {
        return;
    };
    for worker in workers {
        let _ = yayatht_sys::fdpass::send_packet(worker.control.as_raw_fd(), &shutdown);
    }
}

fn wait_dataplanes(workers: &[DataPlaneWorker]) {
    for worker in workers {
        let _ = yayatht_sys::process::wait_pid(worker.pid, false);
    }
}

fn serve_status(instance: &Instance, workers: &[DataPlaneWorker]) -> io::Result<()> {
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
        let metrics = query_dataplane_metrics(workers)?;
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

fn query_dataplane_metrics(workers: &[DataPlaneWorker]) -> io::Result<serde_json::Value> {
    let metrics = workers
        .iter()
        .enumerate()
        .map(|(worker_index, worker)| query_worker_metrics(worker_index, &worker.control))
        .collect::<io::Result<Vec<_>>>()?;
    merge_dataplane_metrics(metrics)
}

fn query_worker_metrics(
    worker_index: usize,
    control_fd: &OwnedFd,
) -> io::Result<serde_json::Value> {
    const REQUEST_ID_BASE: u64 = 0x6d65_7472_6963_7300;
    let request_id = REQUEST_ID_BASE + worker_index as u64;
    control::send(control_fd.as_raw_fd(), Kind::Status, request_id, &[])?;
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut buffer = vec![0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
    loop {
        match control::receive(control_fd.as_raw_fd(), &mut buffer) {
            Ok(message) if message.kind == Kind::Status && message.request_id == request_id => {
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
                        format!("timed out querying data-plane worker {worker_index} metrics"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn merge_dataplane_metrics(metrics: Vec<serde_json::Value>) -> io::Result<serde_json::Value> {
    const INVARIANT_FIELDS: [&str; 3] = ["tap_mtu", "tap_offload", "tap_frame_capacity"];
    let worker_count = metrics.len();
    let mut metrics = metrics.into_iter();
    let mut aggregate = metrics
        .next()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing worker metrics"))?;
    for worker in metrics {
        let worker = worker
            .as_object()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid worker metrics"))?;
        for (key, value) in worker {
            let Some(current) = aggregate.get_mut(key) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("worker metric {key:?} is inconsistent"),
                ));
            };
            if INVARIANT_FIELDS.contains(&key.as_str()) {
                if current != value {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("worker metric {key:?} differs"),
                    ));
                }
                continue;
            }
            let total = current
                .as_u64()
                .zip(value.as_u64())
                .map(|(left, right)| left.saturating_add(right))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("worker metric {key:?} is not an unsigned integer"),
                    )
                })?;
            *current = serde_json::Value::from(total);
        }
    }
    aggregate.insert("workers".to_owned(), serde_json::Value::from(worker_count));
    Ok(serde_json::Value::Object(aggregate))
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

fn kill_dataplanes(workers: &[DataPlaneWorker]) {
    for worker in workers {
        let _ = yayatht_sys::clone::pidfd_send_signal(worker.pidfd.as_raw_fd(), libc::SIGKILL);
    }
    for worker in workers {
        let _ = yayatht_sys::process::wait_pid(worker.pid, false);
    }
}

fn kill_children(workers: &[DataPlaneWorker], namespace_pidfd: &OwnedFd, namespace_pid: i32) {
    for worker in workers {
        let _ = yayatht_sys::clone::pidfd_send_signal(worker.pidfd.as_raw_fd(), libc::SIGKILL);
    }
    let _ = yayatht_sys::clone::pidfd_send_signal(namespace_pidfd.as_raw_fd(), libc::SIGKILL);
    for worker in workers {
        let _ = yayatht_sys::process::wait_pid(worker.pid, false);
    }
    let _ = yayatht_sys::process::wait_pid(namespace_pid, false);
}

struct ChildGuard {
    dataplanes: Vec<(i32, i32)>,
    namespace_pid: i32,
    namespace_pidfd: i32,
    armed: bool,
}

impl ChildGuard {
    fn new(workers: &[DataPlaneWorker], namespace_pid: i32, namespace_pidfd: &OwnedFd) -> Self {
        Self {
            dataplanes: workers
                .iter()
                .map(|worker| (worker.pid, worker.pidfd.as_raw_fd()))
                .collect(),
            namespace_pid,
            namespace_pidfd: namespace_pidfd.as_raw_fd(),
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
        for &(_, pidfd) in &self.dataplanes {
            let _ = yayatht_sys::clone::pidfd_send_signal(pidfd, libc::SIGKILL);
        }
        let _ = yayatht_sys::clone::pidfd_send_signal(self.namespace_pidfd, libc::SIGKILL);
        for &(pid, _) in &self.dataplanes {
            let _ = yayatht_sys::process::wait_pid(pid, false);
        }
        let _ = yayatht_sys::process::wait_pid(self.namespace_pid, false);
    }
}

/// Namespace `resolv.conf` pointing every enabled family at the virtual
/// gateway, where the data plane intercepts 53/UDP and 53/TCP.
fn gateway_resolv_conf(network: &NetworkConfig) -> String {
    let mut contents = String::new();
    if let Some(gateway) = network.gateway_ipv4 {
        let _ = writeln!(contents, "nameserver {gateway}");
    }
    if let Some(gateway) = network.gateway_ipv6 {
        let _ = writeln!(contents, "nameserver {gateway}");
    }
    contents
}

fn debug_failpoint(name: &str) -> io::Result<()> {
    if cfg!(debug_assertions)
        && std::env::var_os("YAYATHT_TEST_FAIL_AT").is_some_and(|value| value == name)
    {
        return Err(io::Error::other(format!("injected failure at {name}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::merge_dataplane_metrics;
    use serde_json::json;

    #[test]
    fn worker_metrics_sum_counters_and_preserve_tap_configuration() {
        let merged = merge_dataplane_metrics(vec![
            json!({
                "tap_rx_packets": 2,
                "active_tcp_flows": 1,
                "tap_mtu": 32000,
                "tap_offload": 1,
                "tap_frame_capacity": 32024
            }),
            json!({
                "tap_rx_packets": 3,
                "active_tcp_flows": 4,
                "tap_mtu": 32000,
                "tap_offload": 1,
                "tap_frame_capacity": 32024
            }),
        ])
        .unwrap();
        assert_eq!(merged["workers"], 2);
        assert_eq!(merged["tap_rx_packets"], 5);
        assert_eq!(merged["active_tcp_flows"], 5);
        assert_eq!(merged["tap_mtu"], 32000);
    }

    #[test]
    fn worker_metrics_reject_inconsistent_tap_configuration() {
        let result =
            merge_dataplane_metrics(vec![json!({"tap_mtu": 1500}), json!({"tap_mtu": 32000})]);
        assert!(result.is_err());
    }
}
