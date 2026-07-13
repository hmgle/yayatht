use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;

fn supported() -> bool {
    if !std::path::Path::new("/dev/net/tun").exists() {
        return false;
    }
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

fn unique_name(label: &str) -> String {
    format!("test-{label}-{}", std::process::id())
}

fn echo_case(bind: SocketAddr, gateway: &str, family_flag: &str, label: &str) {
    if !supported() {
        eprintln!("skipping rootless TAP test: user namespaces or /dev/net/tun unavailable");
        return;
    }
    let listener = TcpListener::bind(bind).expect("bind loopback echo server");
    let port = listener.local_addr().unwrap().port();
    let payload = format!("yayatht-{label}\n").into_bytes();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept proxied connection");
        let mut received = vec![0u8; expected.len()];
        stream
            .read_exact(&mut received)
            .expect("read proxied payload");
        assert_eq!(received, expected);
        stream.write_all(&received).expect("echo proxied payload");
    });

    let name = unique_name(label);
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            family_flag,
            "--name",
            &name,
            "--",
            "busybox",
            "nc",
            "-w",
            "3",
            gateway,
            &port.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn yayatht");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&payload)
        .expect("write command input");
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .expect("wait for yayatht")
        .unwrap_or_else(|| {
            child.kill().expect("kill timed out yayatht");
            panic!("yayatht echo test timed out")
        });
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    assert_eq!(output, payload, "unexpected command output: {stderr}");
    server.join().unwrap();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    assert!(
        !std::path::Path::new(&runtime)
            .join("yayatht")
            .join(name)
            .exists()
    );
}

#[test]
fn ipv4_busybox_echo() {
    echo_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        "--no-ipv6",
        "ipv4",
    );
}

#[test]
fn ipv6_busybox_echo() {
    echo_case(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        "fd79:6179:6174:6874::1",
        "--no-ipv4",
        "ipv6",
    );
}

#[test]
fn target_exit_code_and_cleanup() {
    if !supported() {
        return;
    }
    let name = unique_name("exit");
    let status = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run", "--direct", "--name", &name, "--", "sh", "-c", "exit 42",
        ])
        .status()
        .expect("run exit status test");
    assert_eq!(status.code(), Some(42));
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    assert!(
        !std::path::Path::new(&runtime)
            .join("yayatht")
            .join(name)
            .exists()
    );
}

#[test]
fn status_socket_reports_running_instance() {
    if !supported() {
        return;
    }
    let name = unique_name("status");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/sleep", "1"])
        .spawn()
        .expect("spawn status instance");
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    let socket = std::path::Path::new(&runtime)
        .join("yayatht")
        .join(&name)
        .join("control.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["status", "--name", &name, "--json"])
        .output()
        .expect("query status");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["state"], "running");
    assert_eq!(value["instance_id"], name);
    assert!(child.wait().unwrap().success());
    assert!(!socket.parent().unwrap().exists());
}

#[test]
fn stale_instance_name_is_rejected() {
    if !supported() {
        return;
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    let name = unique_name("collision");
    let directory = std::path::Path::new(&runtime).join("yayatht").join(&name);
    fs::create_dir_all(&directory).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
    assert!(directory.exists());
    fs::remove_dir(directory).unwrap();
}

#[test]
fn injected_namespace_failure_cleans_up() {
    if !supported() {
        return;
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    let name = unique_name("failure");
    let status = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/true"])
        .env("YAYATHT_TEST_FAIL_AT", "ns_tap")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
    assert!(
        !std::path::Path::new(&runtime)
            .join("yayatht")
            .join(name)
            .exists()
    );
}

#[test]
fn two_instances_share_synthetic_addresses_without_collision() {
    if !supported() {
        return;
    }
    thread::scope(|scope| {
        scope.spawn(|| {
            echo_case(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                "192.0.2.1",
                "--no-ipv6",
                "multi-a",
            );
        });
        scope.spawn(|| {
            echo_case(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                "192.0.2.1",
                "--no-ipv6",
                "multi-b",
            );
        });
    });
}

#[test]
fn interrupt_is_forwarded_to_target() {
    if !supported() {
        return;
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    let name = unique_name("signal");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/sleep", "30"])
        .spawn()
        .expect("spawn signal instance");
    let socket = std::path::Path::new(&runtime)
        .join("yayatht")
        .join(&name)
        .join("control.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(status.success());
    let status = child
        .wait_timeout(Duration::from_secs(5))
        .expect("wait after SIGINT")
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("signal was not forwarded")
        });
    assert_eq!(status.code(), Some(130));
    assert!(!socket.parent().unwrap().exists());
}
