use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
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
    echo_payload_case(
        bind,
        gateway,
        family_flag,
        label,
        format!("yayatht-{label}\n").into_bytes(),
        &[],
    );
}

fn echo_payload_case(
    bind: SocketAddr,
    gateway: &str,
    family_flag: &str,
    label: &str,
    payload: Vec<u8>,
    environment: &[(&str, &str)],
) {
    if !supported() {
        eprintln!("skipping rootless TAP test: user namespaces or /dev/net/tun unavailable");
        return;
    }
    let listener = TcpListener::bind(bind).expect("bind loopback echo server");
    let port = listener.local_addr().unwrap().port();
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command.args([
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
    ]);
    for (key, value) in environment {
        command.env(key, value);
    }
    let mut child = command
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

fn proxy_client_case(proxy_args: &[String], label: &str, payload: &[u8]) {
    let name = unique_name(label);
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command.arg("run").args(proxy_args).args([
        "--no-ipv6",
        "--name",
        &name,
        "--",
        "busybox",
        "nc",
        "-w",
        "3",
        "198.51.100.77",
        "443",
    ]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxied yayatht");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload)
        .expect("write proxied command input");
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .expect("wait for proxied yayatht")
        .unwrap_or_else(|| {
            child.kill().expect("kill timed out proxied yayatht");
            panic!("yayatht proxy test timed out")
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
}

fn proxy_stream(listener: TcpListener) -> std::net::TcpStream {
    let (stream, _) = listener.accept().expect("accept proxy connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

fn read_socks_target(stream: &mut std::net::TcpStream) -> SocketAddr {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..3], &[5, 1, 0]);
    let ip = match header[3] {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).unwrap();
            IpAddr::V4(Ipv4Addr::from(address))
        }
        4 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).unwrap();
            IpAddr::V6(Ipv6Addr::from(address))
        }
        other => panic!("unexpected SOCKS5 address type {other}"),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).unwrap();
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

fn proxy_echo(mut stream: std::net::TcpStream, expected: &[u8]) {
    let mut received = vec![0u8; expected.len()];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(received, expected);
    stream.write_all(&received).unwrap();
}

fn credential_files(label: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = std::path::Path::new(&std::env::var_os("XDG_RUNTIME_DIR").unwrap()).join(format!(
        "yayatht-credentials-{label}-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let username = root.join("username");
    let password = root.join("password");
    for (path, value) in [
        (&username, b"proxy-user\n".as_slice()),
        (&password, b"proxy-pass\n".as_slice()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(value).unwrap();
    }
    (root, username, password)
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
fn retransmit_recovers_two_dropped_namespace_segments() {
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        "--no-ipv6",
        "retransmit",
        payload,
        &[("YAYATHT_TEST_DROP_TCP_DATA", "2")],
    );
}

#[test]
fn socks5_no_auth_busybox_echo() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        assert_eq!(
            read_socks_target(&mut stream),
            "198.51.100.77:443".parse().unwrap()
        );
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        proxy_echo(stream, &expected);
    });
    proxy_client_case(
        &["--socks5".to_owned(), address.to_string()],
        "socks5",
        &payload,
    );
    server.join().unwrap();
}

#[test]
fn socks5_password_busybox_echo() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let payload = b"yayatht-socks5-auth\n";
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut greeting = [0u8; 4];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        stream.write_all(&[5, 2]).unwrap();
        let mut auth_header = [0u8; 2];
        stream.read_exact(&mut auth_header).unwrap();
        assert_eq!(auth_header, [1, 10]);
        let mut username = [0u8; 10];
        stream.read_exact(&mut username).unwrap();
        assert_eq!(&username, b"proxy-user");
        let mut password_length = [0u8; 1];
        stream.read_exact(&mut password_length).unwrap();
        assert_eq!(password_length, [10]);
        let mut password = [0u8; 10];
        stream.read_exact(&mut password).unwrap();
        assert_eq!(&password, b"proxy-pass");
        stream.write_all(&[1, 0]).unwrap();
        assert_eq!(
            read_socks_target(&mut stream),
            "198.51.100.77:443".parse().unwrap()
        );
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        proxy_echo(stream, payload);
    });
    let (root, username, password) = credential_files("socks5");
    proxy_client_case(
        &[
            "--socks5".to_owned(),
            address.to_string(),
            "--proxy-username-file".to_owned(),
            username.display().to_string(),
            "--proxy-password-file".to_owned(),
            password.display().to_string(),
        ],
        "socks5-auth",
        payload,
    );
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn socks5_failure_only_closes_one_flow() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let payload = b"yayatht-after-proxy-failure\n";
    let server = thread::spawn(move || {
        let mut failed = proxy_stream(listener.try_clone().unwrap());
        let mut greeting = [0u8; 3];
        failed.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        failed.write_all(&[5, 0]).unwrap();
        assert_eq!(read_socks_target(&mut failed).port(), 80);
        failed.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        drop(failed);

        let mut succeeded = proxy_stream(listener);
        succeeded.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        succeeded.write_all(&[5, 0]).unwrap();
        assert_eq!(read_socks_target(&mut succeeded).port(), 443);
        succeeded
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .unwrap();
        proxy_echo(succeeded, payload);
    });

    let name = unique_name("socks5-failure");
    let script = "busybox nc -w 1 198.51.100.77 80 </dev/null >/dev/null 2>&1 || true; printf 'yayatht-after-proxy-failure\\n' | busybox nc -w 3 198.51.100.77 443";
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--socks5",
            &address.to_string(),
            "--no-ipv6",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("proxy failure isolation test timed out")
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
    assert_eq!(output, payload);
    server.join().unwrap();
}

#[test]
fn http_connect_basic_busybox_echo() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let payload = b"yayatht-http-connect\n";
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("CONNECT 198.51.100.77:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: 198.51.100.77:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNz\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        proxy_echo(stream, payload);
    });
    let (root, username, password) = credential_files("http");
    proxy_client_case(
        &[
            "--http-connect".to_owned(),
            address.to_string(),
            "--proxy-username-file".to_owned(),
            username.display().to_string(),
            "--proxy-password-file".to_owned(),
            password.display().to_string(),
        ],
        "http-connect",
        payload,
    );
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
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
