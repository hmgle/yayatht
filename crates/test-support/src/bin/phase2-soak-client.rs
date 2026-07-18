use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);

fn bind_address(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn tcp_exchange(target: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.write_all(payload)?;
    let mut reply = vec![0u8; payload.len()];
    stream.read_exact(&mut reply)?;
    if reply != payload {
        return Err(std::io::Error::other("TCP echo payload differs"));
    }
    Ok(())
}

fn udp_exchange(target: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind_address(target))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.connect(target)?;
    socket.send(payload)?;
    let mut reply = vec![0u8; payload.len() + 1];
    let length = socket.recv(&mut reply)?;
    if &reply[..length] != payload {
        return Err(std::io::Error::other("UDP echo payload differs"));
    }
    Ok(())
}

fn dns_query(id: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes());
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in [b"phase2".as_slice(), b"soak".as_slice()] {
        message.push(label.len() as u8);
        message.extend_from_slice(label);
    }
    message.push(0);
    message.extend_from_slice(&[0, 1, 0, 1]);
    message
}

fn dns_exchange(target: SocketAddr, id: u16) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind_address(target))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let query = dns_query(id);
    socket.send_to(&query, target)?;
    let mut reply = [0u8; 2048];
    let (length, _) = socket.recv_from(&mut reply)?;
    if length < 12 || reply[..2] != id.to_be_bytes() || reply[3] & 0x0f != 0 {
        return Err(std::io::Error::other("DNS response is invalid"));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("usage: phase2-soak-client SECONDS TCP_TARGET UDP_TARGET DNS_TARGET".into());
    }
    let duration = Duration::from_secs(arguments[1].parse()?);
    let tcp_target: SocketAddr = arguments[2].parse()?;
    let udp_target: SocketAddr = arguments[3].parse()?;
    let dns_target: SocketAddr = arguments[4].parse()?;
    let started = Instant::now();
    let mut iterations = 0u64;
    loop {
        let mut tcp_payload = vec![0x5a; 4096];
        tcp_payload[..8].copy_from_slice(&iterations.to_le_bytes());
        tcp_exchange(tcp_target, &tcp_payload)?;
        let mut udp_payload = vec![0xa5; 1024];
        udp_payload[..8].copy_from_slice(&iterations.to_le_bytes());
        udp_exchange(udp_target, &udp_payload)?;
        dns_exchange(dns_target, iterations as u16)?;
        iterations += 1;
        if started.elapsed() >= duration {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "iterations={iterations} tcp_bytes={} udp_bytes={} dns_queries={iterations}",
        iterations * 4096,
        iterations * 1024,
    );
    Ok(())
}
