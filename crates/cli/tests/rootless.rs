// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;
use yayatht_proxy_proto::{SocksAddress, socks5_udp};

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

#[test]
#[ignore = "executed inside the target namespace by UDP integration cases"]
fn udp_client_process() {
    let mode = std::env::var("YAYATHT_TEST_UDP_CLIENT").expect("UDP client mode");
    let target = std::env::var("YAYATHT_TEST_UDP_TARGET")
        .expect("UDP client target")
        .parse::<SocketAddr>()
        .expect("numeric UDP client target");
    let payload = std::env::var("YAYATHT_TEST_UDP_PAYLOAD")
        .unwrap_or_else(|_| "yayatht-udp-test".to_owned())
        .into_bytes();
    let bind = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = std::net::UdpSocket::bind(bind).expect("bind namespace UDP socket");
    socket
        .connect(target)
        .expect("connect namespace UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.send(&payload).expect("send namespace UDP datagram");
    match mode.as_str() {
        "echo" => {
            let mut reply = vec![0u8; payload.len() + 1];
            let length = socket.recv(&mut reply).expect("receive namespace UDP echo");
            assert_eq!(&reply[..length], payload);
        }
        "refused" => {
            let mut reply = [0u8; 1];
            let error = socket.recv(&mut reply).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        }
        "multi-echo" => {
            let mut reply = vec![0u8; payload.len() + 1];
            let length = socket.recv(&mut reply).expect("receive first UDP echo");
            assert_eq!(&reply[..length], payload);
            let second = std::env::var("YAYATHT_TEST_UDP_TARGET2")
                .expect("second UDP target")
                .parse::<SocketAddr>()
                .expect("numeric second UDP target");
            socket.connect(second).expect("connect second UDP target");
            socket.send(&payload).expect("send second UDP datagram");
            let length = socket.recv(&mut reply).expect("receive second UDP echo");
            assert_eq!(&reply[..length], payload);
        }
        "rebuild" => {
            let mut reply = vec![0u8; payload.len() + 1];
            let length = socket
                .recv(&mut reply)
                .expect("receive pre-rebuild UDP echo");
            assert_eq!(&reply[..length], payload);
            thread::sleep(Duration::from_millis(600));
            socket
                .send(&payload)
                .expect("send post-rebuild UDP datagram");
            let length = socket
                .recv(&mut reply)
                .expect("receive post-rebuild UDP echo");
            assert_eq!(&reply[..length], payload);
        }
        "association-failure-tcp" => {
            thread::sleep(Duration::from_millis(400));
            let tcp_target = std::env::var("YAYATHT_TEST_TCP_TARGET")
                .expect("TCP target")
                .parse::<SocketAddr>()
                .expect("numeric TCP target");
            let mut stream = std::net::TcpStream::connect(tcp_target).expect("connect TCP flow");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(b"tcp-survives").unwrap();
            let mut reply = [0u8; 12];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"tcp-survives");
        }
        "send-only" => thread::sleep(Duration::from_millis(200)),
        other => panic!("unknown UDP client mode {other:?}"),
    }
}

fn status_json(name: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["status", "--name", name, "--json"])
        .output()
        .expect("query status");
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn echo_case(bind: SocketAddr, gateway: &str, family_flag: &str, label: &str) {
    echo_payload_case(
        bind,
        gateway,
        &[family_flag],
        label,
        format!("yayatht-{label}\n").into_bytes(),
        &[],
    );
}

fn echo_payload_case(
    bind: SocketAddr,
    gateway: &str,
    run_flags: &[&str],
    label: &str,
    payload: Vec<u8>,
    environment: &[(&str, &str)],
) -> String {
    if !supported() {
        eprintln!("skipping rootless TAP test: user namespaces or /dev/net/tun unavailable");
        return String::new();
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
    command
        .args(["run", "--direct", "--host-loopback"])
        .args(run_flags)
        .args([
            "--name",
            &name,
            "--",
            "busybox",
            "nc",
            "-w",
            "8",
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
        .expect("wait for yayatht");
    let timed_out = status.is_none();
    let status = match status {
        Some(status) => status,
        None => {
            child.kill().expect("kill timed out yayatht");
            child.wait().expect("reap timed out yayatht")
        }
    };
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
    assert!(!timed_out, "yayatht echo test timed out: {stderr}");
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
    stderr
}

fn udp_echo_case(bind: SocketAddr, gateway: &str, family_flag: &str, label: &str) {
    udp_echo_case_with_flags(bind, gateway, family_flag, label, &[]);
}

fn udp_echo_case_with_flags(
    bind: SocketAddr,
    gateway: &str,
    family_flag: &str,
    label: &str,
    run_flags: &[&str],
) {
    if !supported() {
        eprintln!("skipping rootless TAP test: user namespaces or /dev/net/tun unavailable");
        return;
    }
    let socket = std::net::UdpSocket::bind(bind).expect("bind UDP echo server");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let endpoint = if bind.is_ipv4() {
        format!("{gateway}:{port}")
    } else {
        format!("[{gateway}]:{port}")
    };
    let payload = format!("yayatht-udp-{label}\n").into_bytes();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let mut received = [0u8; 2048];
        let (length, peer) = socket.recv_from(&mut received).expect("receive UDP echo");
        assert_eq!(&received[..length], expected);
        socket
            .send_to(&received[..length], peer)
            .expect("send UDP echo");
    });
    let name = unique_name(label);
    let test_binary = std::env::current_exe().expect("integration test executable");
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command
        .args([
            "run",
            "--direct",
            "--host-loopback",
            family_flag,
            "--dns",
            "off",
        ])
        .args(run_flags)
        .args(["--name", &name, "--"])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", "echo")
        .env("YAYATHT_TEST_UDP_TARGET", endpoint)
        .env(
            "YAYATHT_TEST_UDP_PAYLOAD",
            String::from_utf8(payload).unwrap(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn UDP echo client");
    let status = child
        .wait_timeout(Duration::from_secs(8))
        .expect("wait for UDP echo")
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("UDP echo timed out")
        });
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "UDP echo failed: {stderr}");
    server.join().unwrap();
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

fn read_socks_command(stream: &mut std::net::TcpStream) -> (u8, SocketAddr) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 5);
    assert_eq!(header[2], 0);
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
    (header[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
}

fn read_socks_target(stream: &mut std::net::TcpStream) -> SocketAddr {
    let (command, target) = read_socks_command(stream);
    assert_eq!(command, 1);
    target
}

fn proxy_echo(mut stream: std::net::TcpStream, expected: &[u8]) {
    let mut received = vec![0u8; expected.len()];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(received, expected);
    stream.write_all(&received).unwrap();
}

fn accept_socks5_no_auth(listener: TcpListener, expected_port: u16) -> std::net::TcpStream {
    let mut stream = proxy_stream(listener);
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).unwrap();
    assert_eq!(read_socks_target(&mut stream).port(), expected_port);
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
    stream
}

fn accept_socks5_udp_associate(
    listener: &TcpListener,
    relay: &std::net::UdpSocket,
) -> std::net::TcpStream {
    let mut stream = proxy_stream(listener.try_clone().unwrap());
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).unwrap();
    let (command, client) = read_socks_command(&mut stream);
    assert_eq!(command, 3);
    assert_ne!(client.port(), 0);
    let relay = relay.local_addr().unwrap();
    let SocketAddr::V4(relay) = relay else {
        panic!("test relay must use IPv4");
    };
    let mut response = vec![5, 0, 0, 1];
    // RFC 1928 permits an unspecified BND address. The client must combine
    // its port with the control peer address instead of sending to 0.0.0.0.
    response.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    response.extend_from_slice(&relay.port().to_be_bytes());
    stream.write_all(&response).unwrap();
    stream
}

fn relay_socks5_udp(relay: &std::net::UdpSocket, exchanges: usize) -> Vec<SocketAddr> {
    let mut targets = Vec::with_capacity(exchanges);
    let mut buffer = [0u8; 65_535];
    for _ in 0..exchanges {
        let (length, peer) = relay.recv_from(&mut buffer).unwrap();
        let datagram = socks5_udp::decode(&buffer[..length]).unwrap();
        let socks5_udp::Address::Socket(target) = datagram.destination else {
            panic!("test relay expected an IP target");
        };
        targets.push(target);
        relay.send_to(&buffer[..length], peer).unwrap();
    }
    targets
}

fn relay_socks5_dns(
    relay: &std::net::UdpSocket,
    expected_resolver: SocketAddr,
    expected_name: &str,
    answer: [u8; 4],
) {
    let mut buffer = [0u8; 65_535];
    let (length, peer) = relay.recv_from(&mut buffer).unwrap();
    let datagram = socks5_udp::decode(&buffer[..length]).unwrap();
    assert_eq!(
        datagram.destination,
        socks5_udp::Address::Socket(expected_resolver)
    );
    assert_eq!(dns_qname(datagram.payload), expected_name);
    let query_id = datagram.payload[..2].to_vec();
    let answer = dns_answer_message(datagram.payload, answer, 1);
    assert_eq!(&answer[..2], query_id);
    let length = socks5_udp::encode(
        &mut buffer,
        &SocksAddress::Socket(expected_resolver),
        &answer,
    )
    .unwrap();
    relay.send_to(&buffer[..length], peer).unwrap();
}

fn socks_udp_client_case(
    proxy: SocketAddr,
    label: &str,
    mode: &str,
    target: SocketAddr,
    second_target: Option<SocketAddr>,
) {
    let name = unique_name(label);
    let test_binary = std::env::current_exe().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command
        .args([
            "run",
            "--socks5",
            &proxy.to_string(),
            "--no-ipv6",
            "--dns",
            "off",
            "--name",
            &name,
            "--",
        ])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", mode)
        .env("YAYATHT_TEST_UDP_TARGET", target.to_string())
        .env("YAYATHT_TEST_UDP_PAYLOAD", format!("udp-{label}"));
    if let Some(second) = second_target {
        command.env("YAYATHT_TEST_UDP_TARGET2", second.to_string());
    }
    let output = command.output().expect("run SOCKS5 UDP client");
    assert!(
        output.status.success(),
        "SOCKS5 UDP client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
fn tap_offload_off_preserves_tcp_echo() {
    // --tap-offload=off opens the TAP without IFF_VNET_HDR, so this pins
    // the plain frame layout as an A/B reference for the offload path.
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6", "--tap-offload", "off"],
        "offload-off",
        payload,
        &[],
    );
}

#[test]
fn gro_upload_arrives_in_aggregated_frames() {
    if !supported() {
        return;
    }
    // A bulk namespace upload against a paused reader: while the receive
    // side holds, the namespace kernel coalesces the queued payload into
    // 64 KiB send skbs, so reopening the window forces TSO super-frames
    // larger than one MSS through the TAP, observable as gso_frames_rx.
    // A fast reader could otherwise drain each sub-MSS write immediately
    // and never trigger aggregation. The trailing sleep keeps the
    // instance alive so status can be queried after the transfer.
    const BYTE_COUNT: usize = 4 * 1024 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accept_tx, accept_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (read_tx, read_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        accept_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut received = vec![0u8; BYTE_COUNT];
        stream.read_exact(&mut received).unwrap();
        assert!(received.iter().all(|&byte| byte == 0));
        read_tx.send(()).unwrap();
    });
    let name = unique_name("gro-upload");
    let script = format!(
        "busybox dd if=/dev/zero bs=65536 count=64 2>/dev/null \
         | busybox nc -w 8 192.0.2.1 {port}; busybox sleep 2"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    accept_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // Let the sender queue enough payload behind the closed window that
    // its send skbs coalesce past one MSS.
    thread::sleep(Duration::from_millis(500));
    release_tx.send(()).unwrap();
    read_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let value = status_json(&name);
    assert!(
        value["dataplane"]["gso_frames_rx"].as_u64().unwrap() > 0,
        "no aggregated frame was received: {value}"
    );
    let status = child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("gro upload test timed out")
        });
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    server.join().unwrap();
}

#[test]
fn tso_download_leaves_in_super_frames() {
    if !supported() {
        return;
    }
    // A bulk host->namespace download: the upstream socket buffers more
    // than one MSS, so peeked sends become TSO super-frames the kernel
    // segments at the negotiated MSS, observable as gso_frames_tx. The
    // trailing sleep keeps the instance alive for the status query.
    const BYTE_COUNT: usize = 4 * 1024 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (write_tx, write_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&vec![0u8; BYTE_COUNT]).unwrap();
        write_tx.send(()).unwrap();
    });
    let name = unique_name("tso-download");
    let script = format!(
        "busybox nc -w 8 192.0.2.1 {port} | busybox wc -c; \
         busybox sleep 2"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    server.join().unwrap();
    // Give the namespace reader a moment to drain the tail before the
    // counter is sampled; the assertion only needs one super-frame.
    thread::sleep(Duration::from_millis(300));
    let value = status_json(&name);
    assert!(
        value["dataplane"]["gso_frames_tx"].as_u64().unwrap() > 0,
        "no TSO super-frame was sent: {value}"
    );
    let status = child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("tso download test timed out")
        });
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    assert_eq!(output.trim(), BYTE_COUNT.to_string(), "{stderr}");
}

#[test]
fn watchdog_advances_upstream_ack_without_event_refreshes() {
    if !supported() {
        return;
    }
    const BYTE_COUNT: usize = 48 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (read_tx, read_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = vec![0u8; BYTE_COUNT];
        stream.read_exact(&mut received).unwrap();
        read_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        stream.write_all(&received).unwrap();
    });

    // Every event-driven refresh is suppressed, so the periodic watchdog
    // is the only path that can advance the upstream ACK. The server holds
    // the echo until the counter is checked.
    let name = unique_name("watchdog-ack");
    let script = format!(
        "busybox dd if=/dev/zero bs=1024 count=48 2>/dev/null \
         | busybox nc -w 8 192.0.2.1 {port} | busybox wc -c"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("YAYATHT_TEST_SUPPRESS_EVENT_ACK_REFRESH", "1000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    read_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // The upstream kernel has acknowledged the full payload once the server
    // read it. The watchdog runs on the 100 ms tick while those bytes are
    // outstanding, so 400 ms covers several watchdog passes.
    thread::sleep(Duration::from_millis(400));
    let value = status_json(&name);
    assert!(
        value["dataplane"]["tx_ack_watchdog_advances"]
            .as_u64()
            .unwrap()
            >= 1,
        "watchdog did not advance the upstream ACK: {value}"
    );
    release_tx.send(()).unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("watchdog ack test timed out")
        });
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    assert_eq!(output.trim(), BYTE_COUNT.to_string(), "{stderr}");
    server.join().unwrap();
}

#[test]
fn retransmit_recovers_two_dropped_namespace_segments() {
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6"],
        "retransmit",
        payload,
        &[("YAYATHT_TEST_DROP_TCP_DATA", "2")],
    );
}

#[test]
fn retransmit_recovers_when_the_first_retransmission_is_lost() {
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6"],
        "retransmit-retry",
        payload,
        &[
            ("YAYATHT_TEST_DROP_TCP_DATA", "1"),
            ("YAYATHT_TEST_DROP_TCP_RETRANSMIT", "1"),
        ],
    );
}

#[test]
fn lost_syn_ack_is_retransmitted() {
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6"],
        "syn-ack-loss",
        b"syn-ack-recovered\n".to_vec(),
        &[("YAYATHT_TEST_DROP_TCP_SYN_ACK", "1")],
    );
}

#[test]
fn lost_fin_is_retransmitted() {
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6"],
        "fin-loss",
        b"fin-recovered\n".to_vec(),
        &[("YAYATHT_TEST_DROP_TCP_FIN", "1")],
    );
}

#[test]
fn local_sequence_wrap_survives_a_long_transfer() {
    let payload = (0..32 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6"],
        "sequence-wrap",
        payload,
        &[("YAYATHT_TEST_LOCAL_ISN", "4294963200")],
    );
}

fn half_close_case(label: &str, environment: &[(&str, &str)]) {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"namespace-half\n");
        stream.write_all(b"host-half\n").unwrap();
    });
    let name = unique_name(label);
    let script = format!("printf 'namespace-half\\n' | busybox nc -w 8 192.0.2.1 {port}");
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command.args([
        "run",
        "--direct",
        "--host-loopback",
        "--no-ipv6",
        "--name",
        &name,
        "--",
        "sh",
        "-c",
        &script,
    ]);
    for (key, value) in environment {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "half-close failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"host-half\n");
    server.join().unwrap();
}

#[test]
fn bidirectional_half_close_completes() {
    half_close_case("half-close", &[]);
}

#[test]
fn lost_fin_ack_is_recovered_by_duplicate_fin() {
    half_close_case("fin-ack-loss", &[("YAYATHT_TEST_DROP_TCP_FIN_ACK", "1")]);
}

#[test]
fn zero_window_probe_runs_while_namespace_reader_is_paused() {
    if !supported() {
        return;
    }
    const BYTE_COUNT: usize = 16 * 1024 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept zero-window connection");
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let buffer = [0xa5; 64 * 1024];
        for _ in 0..BYTE_COUNT / buffer.len() {
            stream
                .write_all(&buffer)
                .expect("write zero-window payload");
        }
    });

    let name = unique_name("zero-window");
    let script = format!("busybox nc -w 15 192.0.2.1 {port} | {{ sleep 2; busybox wc -c; }}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("RUST_LOG", "yayatht_dataplane=debug,yayatht=info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(20))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("zero-window test timed out")
        });
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    assert_eq!(output.trim(), BYTE_COUNT.to_string(), "{stderr}");
    assert!(
        stderr.contains("sent TCP zero-window probe"),
        "zero-window probe was not observed: {stderr}"
    );
    server.join().unwrap();
}

#[test]
fn global_pending_limit_applies_instance_backpressure() {
    if !supported() {
        return;
    }
    const BYTE_COUNT: usize = 256 * 1024;
    const GLOBAL_LIMIT: usize = 16 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        accepted_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut buffer = [0u8; 16 * 1024];
        let mut received = 0usize;
        loop {
            let length = stream.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            received += length;
        }
        assert_eq!(received, BYTE_COUNT);
    });

    let name = unique_name("global-pending");
    let script = format!(
        "busybox dd if=/dev/zero bs=4096 count=64 2>/dev/null | busybox nc -w 5 192.0.2.1 {port}"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--max-pending-tcp-bytes",
            &GLOBAL_LIMIT.to_string(),
            "--tcp-send-buffer-bytes",
            &(16 * 1024).to_string(),
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    accepted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    thread::sleep(Duration::from_millis(250));
    let value = status_json(&name);
    assert_eq!(value["dataplane"]["max_pending_tcp_bytes"], GLOBAL_LIMIT);
    assert!(value["dataplane"]["pending_tcp_bytes"].as_u64().unwrap() <= GLOBAL_LIMIT as u64);
    assert!(
        value["dataplane"]["peak_pending_tcp_bytes"]
            .as_u64()
            .unwrap()
            <= GLOBAL_LIMIT as u64
    );
    release_tx.send(()).unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("pending-limit test timed out")
        });
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    server.join().unwrap();
}

#[test]
fn global_retained_limit_caps_socket_backed_retransmit_bytes() {
    if !supported() {
        return;
    }
    const BYTE_COUNT: usize = 256 * 1024;
    const GLOBAL_LIMIT: usize = 16 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (written_tx, written_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let bytes = [0xa5; 16 * 1024];
        for _ in 0..BYTE_COUNT / bytes.len() {
            stream.write_all(&bytes).unwrap();
        }
        written_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });

    let name = unique_name("global-retained");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--name",
            &name,
            "--max-retained-tcp-bytes",
            &GLOBAL_LIMIT.to_string(),
            "--tcp-receive-buffer-bytes",
            &(64 * 1024).to_string(),
            "--",
            "sh",
            "-c",
            &format!("busybox nc -w 5 192.0.2.1 {port} >/dev/null"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    written_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let value = status_json(&name);
    assert_eq!(value["dataplane"]["max_retained_tcp_bytes"], GLOBAL_LIMIT);
    let peak = value["dataplane"]["peak_retained_tcp_bytes"]
        .as_u64()
        .unwrap();
    assert!(
        peak > 0 && peak <= GLOBAL_LIMIT as u64,
        "peak retained bytes: {peak}"
    );
    assert!(
        value["dataplane"]["socket_receive_buffer_bytes"]
            .as_u64()
            .unwrap()
            <= 64 * 1024
    );
    release_tx.send(()).unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("retained-limit test timed out")
        });
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    server.join().unwrap();
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
fn socks5_udp_echo_round_trips_through_association() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let server = thread::spawn(move || {
        let _control = accept_socks5_udp_associate(&listener, &relay);
        let targets = relay_socks5_udp(&relay, 1);
        assert_eq!(targets, ["198.51.100.7:7000".parse().unwrap()]);
    });
    socks_udp_client_case(
        proxy,
        "socks5-udp-echo",
        "echo",
        "198.51.100.7:7000".parse().unwrap(),
        None,
    );
    server.join().unwrap();
}

#[test]
fn association_reuses_one_socket_for_multiple_targets() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let server = thread::spawn(move || {
        let _control = accept_socks5_udp_associate(&listener, &relay);
        let targets = relay_socks5_udp(&relay, 2);
        assert_eq!(
            targets,
            [
                "198.51.100.7:7000".parse().unwrap(),
                "203.0.113.9:9000".parse().unwrap(),
            ]
        );
    });
    socks_udp_client_case(
        proxy,
        "socks5-udp-eim",
        "multi-echo",
        "198.51.100.7:7000".parse().unwrap(),
        Some("203.0.113.9:9000".parse().unwrap()),
    );
    server.join().unwrap();
}

#[test]
fn control_eof_rebuilds_association_with_backoff() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let server = thread::spawn(move || {
        let first = accept_socks5_udp_associate(&listener, &relay);
        relay_socks5_udp(&relay, 1);
        drop(first);
        let _second = accept_socks5_udp_associate(&listener, &relay);
        relay_socks5_udp(&relay, 1);
    });
    socks_udp_client_case(
        proxy,
        "socks5-udp-rebuild",
        "rebuild",
        "198.51.100.7:7000".parse().unwrap(),
        None,
    );
    server.join().unwrap();
}

#[test]
fn association_failure_leaves_tcp_flows_untouched() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server = thread::spawn(move || {
        let first = accept_socks5_udp_associate(&listener, &relay);
        drop(first);
        let mut rebuilt_controls = Vec::new();
        loop {
            let mut stream = proxy_stream(listener.try_clone().unwrap());
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let (command, target) = read_socks_command(&mut stream);
            match command {
                1 => {
                    assert_eq!(target, "198.51.100.8:443".parse().unwrap());
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    proxy_echo(stream, b"tcp-survives");
                    break;
                }
                3 => {
                    let relay_address = relay.local_addr().unwrap();
                    let SocketAddr::V4(relay_address) = relay_address else {
                        unreachable!();
                    };
                    let mut response = vec![5, 0, 0, 1];
                    response.extend_from_slice(&relay_address.ip().octets());
                    response.extend_from_slice(&relay_address.port().to_be_bytes());
                    stream.write_all(&response).unwrap();
                    rebuilt_controls.push(stream);
                }
                other => panic!("unexpected SOCKS command {other}"),
            }
        }
    });
    let name = unique_name("socks5-udp-failure-isolation");
    let test_binary = std::env::current_exe().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--socks5",
            &proxy.to_string(),
            "--no-ipv6",
            "--dns",
            "off",
            "--name",
            &name,
            "--",
        ])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", "association-failure-tcp")
        .env("YAYATHT_TEST_UDP_TARGET", "198.51.100.7:7000")
        .env("YAYATHT_TEST_TCP_TARGET", "198.51.100.8:443")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "association failure damaged TCP: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
fn http_connect_udp_returns_port_unreachable() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let name = unique_name("http-udp-unreachable");
    let test_binary = std::env::current_exe().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--http-connect",
            &proxy.to_string(),
            "--no-ipv6",
            "--dns",
            "off",
            "--name",
            &name,
            "--",
        ])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", "refused")
        .env("YAYATHT_TEST_UDP_TARGET", "198.51.100.7:7000")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "HTTP UDP policy did not return ICMP: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(listener);
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
fn proxy_exit_during_handshake_does_not_stall_the_instance() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
    });
    let name = unique_name("proxy-handshake-exit");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--socks5",
            &address.to_string(),
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
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("proxy handshake exit test timed out")
        });
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_ne!(status.code(), Some(125), "data plane failed: {stderr}");
    server.join().unwrap();
}

#[test]
fn proxy_exit_after_partial_write_only_closes_that_flow() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let payload = b"after-partial-proxy-exit\n";
    let server = thread::spawn(move || {
        let mut partial = accept_socks5_no_auth(listener.try_clone().unwrap(), 80);
        let mut received = [0u8; 1024];
        partial.read_exact(&mut received).unwrap();
        drop(partial);

        let succeeded = accept_socks5_no_auth(listener, 443);
        proxy_echo(succeeded, payload);
    });
    let name = unique_name("proxy-partial-exit");
    let script = "busybox dd if=/dev/zero bs=4096 count=16 2>/dev/null | busybox nc -w 3 198.51.100.77 80 >/dev/null 2>&1 || true; printf 'after-partial-proxy-exit\\n' | busybox nc -w 3 198.51.100.77 443";
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
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
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "partial proxy exit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);
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
fn sandbox_on_by_default_runs_busybox_echo() {
    echo_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        "--no-ipv6",
        "sandbox-default",
    );
}

#[test]
fn direct_udp_echo_round_trips() {
    udp_echo_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        "--no-ipv6",
        "udp4-echo",
    );
}

#[test]
fn ipv6_direct_udp_echo_round_trips() {
    udp_echo_case(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        "fd79:6179:6174:6874::1",
        "--no-ipv4",
        "udp6-echo",
    );
}

#[test]
fn four_workers_preserve_tcp_echo() {
    echo_payload_case(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        "192.0.2.1",
        &["--no-ipv6", "--workers", "4"],
        "four-worker-tcp",
        vec![0x5a; 32 * 1024],
        &[],
    );
}

#[test]
fn udp_off_drops_namespace_datagrams() {
    if !supported() {
        return;
    }
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let name = unique_name("udp-off-drop");
    let test_binary = std::env::current_exe().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--udp",
            "off",
            "--dns",
            "off",
            "--name",
            &name,
            "--",
        ])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", "send-only")
        .env("YAYATHT_TEST_UDP_TARGET", format!("192.0.2.1:{port}"));
    let output = command.output().expect("run UDP-off client");
    assert!(output.status.success());
    let mut received = [0u8; 32];
    let error = socket.recv_from(&mut received).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}

#[test]
fn udp_port_unreachable_synthesizes_icmpv4() {
    if !supported() {
        return;
    }
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let name = unique_name("udp4-unreachable");
    let test_binary = std::env::current_exe().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--dns",
            "off",
            "--name",
            &name,
            "--",
        ])
        .arg(test_binary)
        .args(["--ignored", "--exact", "udp_client_process", "--quiet"])
        .env("YAYATHT_TEST_UDP_CLIENT", "refused")
        .env("YAYATHT_TEST_UDP_TARGET", format!("192.0.2.1:{port}"));
    let output = command.output().expect("run closed-port UDP client");
    assert!(
        output.status.success(),
        "namespace did not receive ICMP Port Unreachable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sandbox_off_runs_busybox_echo() {
    if !supported() {
        return;
    }
    let stderr = echo_payload_case(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "192.0.2.1",
        &["--no-ipv6", "--sandbox", "off"],
        "sandbox-off",
        b"sandbox-off\n".to_vec(),
        &[],
    );
    assert!(stderr.contains("sandbox disabled: role seccomp"));
}

#[test]
fn forbidden_syscall_kills_the_data_plane() {
    if !supported() {
        return;
    }
    let name = unique_name("sandbox-forbidden");
    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/true"])
        .env("YAYATHT_TEST_FAIL_AT", "dp_forbidden_syscall")
        .output()
        .expect("run forbidden-syscall test");
    assert_eq!(output.status.code(), Some(125));
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    assert!(
        !std::path::Path::new(&runtime)
            .join("yayatht")
            .join(name)
            .exists()
    );
}

#[test]
fn forbidden_syscall_kills_namespace_init() {
    if !supported() {
        return;
    }
    let name = unique_name("namespace-seccomp");
    let status = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/sleep", "30"])
        .env("YAYATHT_TEST_FAIL_AT", "ns_forbidden_syscall")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    assert!(
        !std::path::Path::new(&runtime)
            .join("yayatht")
            .join(name)
            .exists()
    );
}

#[test]
fn forbidden_syscall_kills_supervisor() {
    if !supported() {
        return;
    }
    let root = std::env::temp_dir().join(unique_name("supervisor-seccomp-root"));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let name = unique_name("supervisor-seccomp");
    let status = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--runtime-dir",
            root.to_str().unwrap(),
            "--name",
            &name,
            "--",
            "/bin/sleep",
            "30",
        ])
        .env("YAYATHT_TEST_FAIL_AT", "supervisor_forbidden_syscall")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGSYS));

    let metadata = fs::read(root.join(&name).join("instance.json")).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    let mut pids = metadata["dataplane_worker_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pid| pid.as_i64().unwrap())
        .collect::<Vec<_>>();
    pids.push(metadata["namespace_init_pid"].as_i64().unwrap());
    for _ in 0..100 {
        if pids
            .iter()
            .all(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists())
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        pids.iter()
            .all(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists()),
        "sandboxed descendants survived supervisor death: {pids:?}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pivoted_data_plane_still_serves_status() {
    if !supported() {
        return;
    }
    let name = unique_name("sandbox-pivot");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/sleep", "1"])
        .spawn()
        .expect("spawn sandbox status instance");
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
    let value = status_json(&name);
    let dataplane_pid = value["dataplane_pid"].as_i64().unwrap();
    let mountinfo = fs::read_to_string(format!("/proc/{dataplane_pid}/mountinfo")).unwrap();
    let root = mountinfo
        .lines()
        .find(|line| line.split_whitespace().nth(4) == Some("/"))
        .expect("data-plane root mount");
    assert!(
        root.contains(" - tmpfs tmpfs "),
        "unexpected root mount: {root}"
    );
    assert!(child.wait().unwrap().success());
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
    assert_eq!(
        value["dataplane"]["max_pending_tcp_bytes"],
        64 * 1024 * 1024
    );
    assert_eq!(
        value["dataplane"]["max_retained_tcp_bytes"],
        64 * 1024 * 1024
    );
    assert_eq!(value["dataplane"]["flow_fd_limit"], 16_416);
    assert_eq!(value["dataplane"]["tap_mtu"], 32_000);
    assert_eq!(value["dataplane"]["tap_offload"], 1);
    // MTU + Ethernet header + the 10-byte virtio_net_hdr prefix.
    assert_eq!(value["dataplane"]["tap_frame_capacity"], 32_024);
    assert_eq!(value["dataplane"]["tap_frame_pool_frames"], 523);
    let dataplane_pid = value["dataplane_pid"].as_i64().unwrap();
    let limits = fs::read_to_string(format!("/proc/{dataplane_pid}/limits")).unwrap();
    let open_files = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .expect("data-plane RLIMIT_NOFILE entry");
    assert!(
        open_files.split_whitespace().any(|field| field == "16416"),
        "unexpected data-plane fd limit: {open_files}"
    );
    let core_size = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .expect("data-plane RLIMIT_CORE entry");
    assert!(
        core_size
            .split_whitespace()
            .filter(|field| *field == "0")
            .count()
            >= 2,
        "unexpected data-plane core limit: {core_size}"
    );
    assert!(child.wait().unwrap().success());
    assert!(!socket.parent().unwrap().exists());
}

#[test]
fn default_is_single_worker() {
    if !supported() {
        return;
    }
    let name = unique_name("default-worker");
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args(["run", "--direct", "--name", &name, "--", "/bin/sleep", "1"])
        .spawn()
        .expect("spawn default worker instance");
    thread::sleep(Duration::from_millis(100));
    let value = status_json(&name);
    assert_eq!(value["dataplane"]["workers"], 1);
    assert_eq!(value["dataplane_worker_pids"].as_array().unwrap().len(), 1);
    assert_eq!(value["dataplane_pid"], value["dataplane_worker_pids"][0]);
    assert!(child.wait().unwrap().success());
}

#[test]
fn status_aggregates_worker_metrics() {
    if !supported() {
        return;
    }
    const FLOWS: usize = 8;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (complete_tx, complete_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for _ in 0..FLOWS {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
        }
        complete_tx.send(()).unwrap();
    });
    let name = unique_name("worker-status");
    let script = format!(
        "for i in 1 2 3 4 5 6 7 8; do printf x | busybox nc -w 3 192.0.2.1 {port}; done; \
         busybox sleep 2"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--dns",
            "off",
            "--workers",
            "4",
            "--name",
            &name,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    complete_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let value = status_json(&name);
    assert_eq!(value["dataplane"]["workers"], 4);
    assert_eq!(value["dataplane_worker_pids"].as_array().unwrap().len(), 4);
    assert_eq!(value["dataplane"]["tcp_created"], FLOWS);
    assert!(value["dataplane"]["tap_rx_packets"].as_u64().unwrap() > FLOWS as u64);
    assert!(child.wait().unwrap().success());
    server.join().unwrap();
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

fn namespace_output(
    run_args: &[&str],
    target: &[&str],
    environment: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yayatht"));
    command.args(["run"]).args(run_args).arg("--").args(target);
    for (key, value) in environment {
        command.env(key, value);
    }
    command.output().expect("run yayatht")
}

#[test]
fn resolv_conf_is_bind_mounted_with_gateway_nameservers() {
    if !supported() {
        return;
    }
    let output = namespace_output(&["--direct"], &["busybox", "cat", "/etc/resolv.conf"], &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nameserver 192.0.2.1"),
        "missing IPv4 gateway nameserver: {stdout}"
    );
    assert!(
        stdout.contains("nameserver fd79:6179:6174:6874::1"),
        "missing IPv6 gateway nameserver: {stdout}"
    );
}

#[test]
fn dns_off_keeps_the_host_resolv_conf() {
    if !supported() {
        return;
    }
    let output = namespace_output(
        &["--direct", "--dns", "off"],
        &["busybox", "cat", "/etc/resolv.conf"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("nameserver 192.0.2.1"),
        "gateway nameserver mounted despite --dns off: {stdout}"
    );
}

#[test]
fn tcp_dns_is_redirected_to_the_resolver_through_the_proxy() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock proxy");
    let proxy = listener.local_addr().unwrap();
    let payload = b"dns-stream-semantics".to_vec();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let target = read_socks_target(&mut stream);
        assert_eq!(
            target,
            "203.0.113.53:53".parse::<SocketAddr>().unwrap(),
            "gateway TCP DNS must CONNECT to the configured resolver"
        );
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        proxy_echo(stream, &expected);
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--socks5",
            &proxy.to_string(),
            "--dns-upstream",
            "203.0.113.53",
            "--",
            "busybox",
            "nc",
            "-w",
            "8",
            "192.0.2.1",
            "53",
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
        .expect("write query stream");
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .expect("wait for yayatht");
    let status = status.unwrap_or_else(|| {
        child.kill().unwrap();
        panic!("TCP DNS redirect test timed out")
    });
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "yayatht failed: {stderr}");
    assert_eq!(stdout, payload, "unexpected stream payload: {stderr}");
    server.join().unwrap();
}

#[test]
fn tcp_dns_without_a_resolver_is_refused() {
    if !supported() {
        return;
    }
    let resolv = std::env::temp_dir().join(format!("yayatht-empty-resolv-{}", std::process::id()));
    fs::write(&resolv, "# no nameservers\n").unwrap();
    let output = namespace_output(
        &["--direct"],
        &["busybox", "nc", "-w", "4", "192.0.2.1", "53"],
        &[("YAYATHT_RESOLV_CONF", resolv.to_str().unwrap())],
    );
    fs::remove_file(&resolv).ok();
    assert!(
        !output.status.success(),
        "gateway DNS connect must be refused without a resolver"
    );
    assert!(
        output.stdout.is_empty(),
        "refused connection produced output: {:?}",
        output.stdout
    );
}

fn dns_client_binary() -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_yayatht"))
        .parent()?
        .join("dns-client");
    path.exists().then(|| path.to_str().unwrap().to_owned())
}

fn read_dns_query(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).ok()?;
    let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut query).ok()?;
    Some(query)
}

fn dns_qname(query: &[u8]) -> String {
    let mut name = String::new();
    let mut offset = 12;
    while query[offset] != 0 {
        let length = usize::from(query[offset]);
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(&query[offset + 1..offset + 1 + length]).unwrap());
        offset += length + 1;
    }
    name
}

/// Response echoing the query's ID and question with `count` A records.
fn dns_answer_message(query: &[u8], ip: [u8; 4], count: u16) -> Vec<u8> {
    let mut offset = 12;
    while query[offset] != 0 {
        offset += usize::from(query[offset]) + 1;
    }
    let question_end = offset + 5;
    let mut message = Vec::new();
    message.extend_from_slice(&query[..2]);
    message.extend_from_slice(&0x8180u16.to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    message.extend_from_slice(&count.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(&query[12..question_end]);
    for _ in 0..count {
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        message.extend_from_slice(&ip);
    }
    message
}

fn write_dns_frame(stream: &mut std::net::TcpStream, message: &[u8]) {
    let length = u16::try_from(message.len()).unwrap();
    stream.write_all(&length.to_be_bytes()).unwrap();
    stream.write_all(message).unwrap();
}

/// Serves length-prefixed DNS on one connection until EOF; `lookup`
/// returning None swallows the query without answering.
fn serve_dns_connection(
    mut stream: std::net::TcpStream,
    lookup: impl Fn(&str) -> Option<([u8; 4], u16)>,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    while let Some(query) = read_dns_query(&mut stream) {
        if let Some((ip, count)) = lookup(&dns_qname(&query)) {
            let answer = dns_answer_message(&query, ip, count);
            write_dns_frame(&mut stream, &answer);
        }
    }
}

/// Accepts resolver connections forever; leaked at test exit by design.
fn spawn_mock_resolver(
    listener: TcpListener,
    lookup: impl Fn(&str) -> Option<([u8; 4], u16)> + Clone + Send + 'static,
) {
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let lookup = lookup.clone();
            thread::spawn(move || serve_dns_connection(stream, lookup));
        }
    });
}

#[test]
fn four_workers_preserve_udp_and_dns() {
    if !supported() {
        return;
    }
    udp_echo_case_with_flags(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        "192.0.2.1",
        "--no-ipv6",
        "four-worker-udp",
        &["--workers", "4"],
    );

    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let resolver = listener.local_addr().unwrap();
    spawn_mock_resolver(listener, |name| {
        assert_eq!(name, "four-worker.test");
        Some(([198, 51, 100, 55], 1))
    });
    let output = namespace_output(
        &[
            "--direct",
            "--workers",
            "4",
            "--no-ipv6",
            "--dns-upstream",
            &resolver.to_string(),
        ],
        &[&client, "query", "192.0.2.1", "four-worker.test"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("a=198.51.100.55") && stdout.contains("id=ok"),
        "unexpected DNS result: {stdout} {stderr}"
    );
}

#[test]
fn proxy_udp_requires_socks5() {
    for upstream in [vec!["--direct"], vec!["--http-connect", "127.0.0.1:9"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
            .arg("run")
            .args(upstream)
            .args(["--dns", "proxy-udp", "--", "true"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--dns proxy-udp requires --socks5"),
            "unexpected validation error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_yayatht"))
        .args([
            "run",
            "--socks5",
            "127.0.0.1:9",
            "--dns",
            "proxy-udp",
            "--udp",
            "off",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--dns proxy-udp requires --udp on"));
}

#[test]
fn udp_dns_resolves_through_an_association() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let resolver = "203.0.113.53:53".parse().unwrap();
    let server = thread::spawn(move || {
        let _control = accept_socks5_udp_associate(&listener, &relay);
        relay_socks5_dns(&relay, resolver, "proxy-udp.test", [198, 51, 100, 53]);
    });
    let output = namespace_output(
        &[
            "--socks5",
            &proxy.to_string(),
            "--dns",
            "proxy-udp",
            "--dns-upstream",
            &resolver.to_string(),
            "--no-ipv6",
        ],
        &[&client, "query", "192.0.2.1", "proxy-udp.test"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("rcode=0")
            && stdout.contains("a=198.51.100.53")
            && stdout.contains("id=ok"),
        "unexpected DNS result: {stdout} {stderr}"
    );
    server.join().unwrap();
}

#[test]
fn ipv6_udp_dns_resolves_through_association() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let resolver = "[2001:db8::53]:53".parse().unwrap();
    let server = thread::spawn(move || {
        let _control = accept_socks5_udp_associate(&listener, &relay);
        relay_socks5_dns(&relay, resolver, "proxy-udp-v6.test", [198, 51, 100, 54]);
    });
    let output = namespace_output(
        &[
            "--socks5",
            &proxy.to_string(),
            "--dns",
            "proxy-udp",
            "--dns-upstream",
            &resolver.to_string(),
            "--no-ipv4",
        ],
        &[
            &client,
            "query",
            "fd79:6179:6174:6874::1",
            "proxy-udp-v6.test",
        ],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("rcode=0")
            && stdout.contains("a=198.51.100.54")
            && stdout.contains("id=ok"),
        "unexpected IPv6 DNS result: {stdout} {stderr}"
    );
    server.join().unwrap();
}

#[test]
fn udp_dns_resolves_through_a_dedicated_proxy_tunnel() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock proxy");
    let proxy = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = proxy_stream(listener);
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let target = read_socks_target(&mut stream);
        assert_eq!(
            target,
            "203.0.113.53:53".parse::<SocketAddr>().unwrap(),
            "resolver tunnel must CONNECT to the configured resolver"
        );
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        serve_dns_connection(stream, |name| {
            assert_eq!(name, "example.com");
            Some(([198, 51, 100, 7], 1))
        });
    });
    let output = namespace_output(
        &[
            "--socks5",
            &proxy.to_string(),
            "--dns-upstream",
            "203.0.113.53",
        ],
        &[&client, "query", "192.0.2.1", "example.com"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("rcode=0")
            && stdout.contains("a=198.51.100.7")
            && stdout.contains("tc=0")
            && stdout.contains("id=ok"),
        "unexpected DNS result: {stdout} {stderr}"
    );
    server.join().unwrap();
}

#[test]
fn same_id_queries_return_out_of_order_to_the_right_clients() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock resolver");
    let resolver = listener.local_addr().unwrap();
    // Read both queries before answering, then answer in reverse order.
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept resolver connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let first = read_dns_query(&mut stream).expect("first query");
        let second = read_dns_query(&mut stream).expect("second query");
        for query in [&second, &first] {
            let ip = if dns_qname(query) == "alpha.test" {
                [198, 51, 100, 1]
            } else {
                [198, 51, 100, 2]
            };
            let answer = dns_answer_message(query, ip, 1);
            write_dns_frame(&mut stream, &answer);
        }
    });
    let output = namespace_output(
        &["--direct", "--dns-upstream", &resolver.to_string()],
        &[&client, "same-id", "192.0.2.1", "alpha.test", "beta.test"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("alpha.test") && stdout.contains("a=198.51.100.1"),
        "alpha answer misrouted: {stdout} {stderr}"
    );
    assert!(
        stdout.contains("beta.test") && stdout.contains("a=198.51.100.2"),
        "beta answer misrouted: {stdout} {stderr}"
    );
    assert_eq!(
        stdout.matches("id=ok").count(),
        2,
        "IDs not restored: {stdout}"
    );
}

#[test]
fn oversized_udp_answer_truncates_and_tcp_retry_succeeds() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock resolver");
    let resolver = listener.local_addr().unwrap();
    // 60 A records: far past the 512-byte plain-UDP limit.
    spawn_mock_resolver(listener, |_| Some(([198, 51, 100, 3], 60)));
    let output = namespace_output(
        &["--direct", "--dns-upstream", &resolver.to_string()],
        &[&client, "tc-fallback", "192.0.2.1", "big.test"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(stdout.contains("udp tc"), "expected truncation: {stdout}");
    assert!(
        stdout.contains("tcp rcode=0") && stdout.contains("answers=60") && stdout.contains("id=ok"),
        "TCP retry failed: {stdout} {stderr}"
    );
}

#[test]
fn edns0_payload_size_avoids_truncation() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock resolver");
    let resolver = listener.local_addr().unwrap();
    spawn_mock_resolver(listener, |_| Some(([198, 51, 100, 4], 60)));
    let output = namespace_output(
        &["--direct", "--dns-upstream", &resolver.to_string()],
        &[&client, "edns", "192.0.2.1", "big.test", "4096"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("tc=0") && stdout.contains("answers=60"),
        "EDNS0 answer truncated: {stdout} {stderr}"
    );
}

#[test]
fn malformed_query_is_answered_formerr_without_contacting_the_resolver() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    // TEST-NET resolver: any contact would hang, proving the local answer.
    let output = namespace_output(
        &["--direct", "--dns-upstream", "203.0.113.53"],
        &[&client, "malformed", "192.0.2.1", "example.com"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("rcode=1") && stdout.contains("id=ok"),
        "expected FORMERR: {stdout} {stderr}"
    );
}

#[test]
fn unanswered_query_times_out_with_servfail() {
    if !supported() {
        return;
    }
    let Some(client) = dns_client_binary() else {
        eprintln!("skipping DNS test: dns-client helper not built");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock resolver");
    let resolver = listener.local_addr().unwrap();
    spawn_mock_resolver(listener, |_| None);
    let output = namespace_output(
        &["--direct", "--dns-upstream", &resolver.to_string()],
        &[&client, "query", "192.0.2.1", "slow.test"],
        &[("YAYATHT_TEST_DNS_QUERY_TIMEOUT_MS", "300")],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("rcode=2") && stdout.contains("id=ok"),
        "expected SERVFAIL: {stdout} {stderr}"
    );
}

#[test]
fn busybox_nslookup_resolves_through_the_default_dns_mode() {
    if !supported() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock resolver");
    let resolver = listener.local_addr().unwrap();
    spawn_mock_resolver(listener, |_| Some(([192, 0, 2, 99], 1)));
    let output = namespace_output(
        &["--direct", "--dns-upstream", &resolver.to_string()],
        &["busybox", "nslookup", "example.com", "192.0.2.1"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "yayatht failed: {stderr}");
    assert!(
        stdout.contains("192.0.2.99"),
        "nslookup missing answer: {stdout} {stderr}"
    );
}
