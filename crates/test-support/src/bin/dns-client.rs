//! Minimal DNS test client run inside the namespace by the rootless
//! integration suite. Prints machine-checkable summaries; the host test
//! asserts on stdout.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(3);
const FLAG_RD: u16 = 0x0100;
const FLAG_TC: u16 = 0x0200;

fn build_query(id: u16, name: &str, edns_payload: Option<u16>) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&FLAG_RD.to_be_bytes());
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    message.extend_from_slice(&u16::from(edns_payload.is_some()).to_be_bytes());
    for label in name.split('.') {
        message.push(u8::try_from(label.len()).expect("label fits"));
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&[0, 1, 0, 1]);
    if let Some(payload) = edns_payload {
        message.push(0); // root
        message.extend_from_slice(&41u16.to_be_bytes());
        message.extend_from_slice(&payload.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    message
}

struct Response {
    id: u16,
    rcode: u8,
    truncated: bool,
    answers: u16,
    first_a: Option<Ipv4Addr>,
    len: usize,
}

fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)?;
        match length {
            0 => return Some(offset + 1),
            _ if length & 0xc0 == 0xc0 => return Some(offset + 2),
            _ => offset += usize::from(length) + 1,
        }
    }
}

fn parse_response(message: &[u8]) -> Option<Response> {
    if message.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let answers = u16::from_be_bytes([message[6], message[7]]);
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(message, offset)? + 4;
    }
    let mut first_a = None;
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            break;
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let rdlength = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset += 10;
        if record_type == 1 && rdlength == 4 && offset + 4 <= message.len() && first_a.is_none() {
            first_a = Some(Ipv4Addr::new(
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            ));
        }
        offset += rdlength;
    }
    Some(Response {
        id: u16::from_be_bytes([message[0], message[1]]),
        rcode: (flags & 0x000f) as u8,
        truncated: flags & FLAG_TC != 0,
        answers,
        first_a,
        len: message.len(),
    })
}

fn udp_exchange(server: SocketAddr, message: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).expect("bind UDP socket");
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.send_to(message, server).expect("send query");
    let mut buffer = vec![0u8; 65_535];
    let (length, _) = socket.recv_from(&mut buffer).ok()?;
    buffer.truncate(length);
    Some(buffer)
}

fn tcp_exchange(server: SocketAddr, message: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(server).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    let length = u16::try_from(message.len()).expect("query fits");
    stream.write_all(&length.to_be_bytes()).ok()?;
    stream.write_all(message).ok()?;
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).ok()?;
    let mut frame = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

fn describe(sent_id: u16, raw: Option<Vec<u8>>) -> String {
    match raw.as_deref().and_then(parse_response) {
        None => "timeout".to_owned(),
        Some(response) => format!(
            "rcode={} tc={} answers={} a={} len={} id={}",
            response.rcode,
            u8::from(response.truncated),
            response.answers,
            response
                .first_a
                .map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
            response.len,
            if response.id == sent_id { "ok" } else { "bad" },
        ),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mode = arguments.get(1).expect("mode").as_str();
    let server: SocketAddr = SocketAddr::new(
        arguments
            .get(2)
            .expect("server")
            .parse()
            .expect("server IP"),
        53,
    );
    match mode {
        "query" => {
            let message = build_query(0x2b1d, &arguments[3], None);
            println!("udp {}", describe(0x2b1d, udp_exchange(server, &message)));
        }
        "edns" => {
            let payload: u16 = arguments[4].parse().expect("payload size");
            let message = build_query(0x2b1e, &arguments[3], Some(payload));
            println!("udp {}", describe(0x2b1e, udp_exchange(server, &message)));
        }
        "tcp" => {
            let message = build_query(0x2b1f, &arguments[3], None);
            println!("tcp {}", describe(0x2b1f, tcp_exchange(server, &message)));
        }
        // Two sockets, the SAME DNS ID, different names: responses must
        // come back to the right source endpoint regardless of upstream
        // answer order.
        "same-id" => {
            let sockets: Vec<UdpSocket> = (0..2)
                .map(|_| {
                    let socket = UdpSocket::bind(("0.0.0.0", 0)).expect("bind UDP socket");
                    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
                    socket
                })
                .collect();
            for (socket, name) in sockets.iter().zip(&arguments[3..5]) {
                socket
                    .send_to(&build_query(0x7777, name, None), server)
                    .expect("send query");
            }
            for (socket, name) in sockets.iter().zip(&arguments[3..5]) {
                let mut buffer = vec![0u8; 4096];
                let raw = socket
                    .recv_from(&mut buffer)
                    .ok()
                    .map(|(length, _)| buffer[..length].to_vec());
                println!("{name} {}", describe(0x7777, raw));
            }
        }
        // UDP first; on TC retry the same question over TCP/53.
        "tc-fallback" => {
            let message = build_query(0x1c1c, &arguments[3], None);
            match udp_exchange(server, &message)
                .as_deref()
                .and_then(parse_response)
            {
                None => println!("udp timeout"),
                Some(response) if response.truncated => {
                    println!("udp tc");
                    println!("tcp {}", describe(0x1c1c, tcp_exchange(server, &message)));
                }
                Some(_) => println!("udp not-truncated"),
            }
        }
        // Valid header, two questions: the proxy must answer FORMERR.
        "malformed" => {
            let mut message = build_query(0x0bad, &arguments[3], None);
            message[5] = 2;
            println!("udp {}", describe(0x0bad, udp_exchange(server, &message)));
        }
        other => panic!("unknown mode {other}"),
    }
}
