use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
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
    assert_eq!(value["dataplane"]["flow_fd_limit"], 4096 + 32);
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
        open_files.split_whitespace().any(|field| field == "4128"),
        "unexpected data-plane fd limit: {open_files}"
    );
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
