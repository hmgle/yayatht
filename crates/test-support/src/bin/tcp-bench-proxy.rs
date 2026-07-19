// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;

const MAX_HTTP_HEADERS: usize = 8 * 1024;

#[derive(Clone)]
enum Mode {
    Socks5 {
        credentials: Option<(String, String)>,
        redirect_host: Option<String>,
    },
    Http {
        credentials: Option<(String, String)>,
        redirect_host: Option<String>,
    },
}

enum Target {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl Target {
    fn connect(&self, redirect_host: Option<&str>) -> std::io::Result<TcpStream> {
        if let Some(host) = redirect_host {
            let port = match self {
                Self::Socket(address) => address.port(),
                Self::Domain(_, port) => *port,
            };
            return TcpStream::connect((host, port));
        }
        match self {
            Self::Socket(address) => TcpStream::connect(address),
            Self::Domain(host, port) => TcpStream::connect((host.as_str(), *port)),
        }
    }
}

fn usage() -> &'static str {
    "usage: tcp-bench-proxy socks5|http PORT [REDIRECT_HOST [USERNAME PASSWORD]]"
}

fn read_socks_target(stream: &mut TcpStream) -> Result<Target, Box<dyn Error>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[..3] != [5, 1, 0] {
        return Err("invalid SOCKS5 CONNECT request".into());
    }
    let target = match header[3] {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address)?;
            Target::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(address)), 0))
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut host = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut host)?;
            Target::Domain(String::from_utf8(host)?, 0)
        }
        4 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address)?;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), 0))
        }
        _ => return Err("unsupported SOCKS5 address type".into()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    Ok(match target {
        Target::Socket(mut address) => {
            address.set_port(port);
            Target::Socket(address)
        }
        Target::Domain(host, _) => Target::Domain(host, port),
    })
}

fn socks5_handshake(
    stream: &mut TcpStream,
    credentials: Option<&(String, String)>,
    redirect_host: Option<&str>,
) -> Result<TcpStream, Box<dyn Error>> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting[0] != 5 {
        return Err("invalid SOCKS5 greeting".into());
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods)?;
    let method = if credentials.is_some() { 2 } else { 0 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 0xff])?;
        return Err("required SOCKS5 authentication method was not offered".into());
    }
    stream.write_all(&[5, method])?;
    if let Some((expected_user, expected_password)) = credentials {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;
        if header[0] != 1 {
            return Err("invalid SOCKS5 auth version".into());
        }
        let mut username = vec![0u8; usize::from(header[1])];
        stream.read_exact(&mut username)?;
        let mut password_length = [0u8; 1];
        stream.read_exact(&mut password_length)?;
        let mut password = vec![0u8; usize::from(password_length[0])];
        stream.read_exact(&mut password)?;
        let accepted =
            username == expected_user.as_bytes() && password == expected_password.as_bytes();
        stream.write_all(&[1, u8::from(!accepted)])?;
        if !accepted {
            return Err("invalid SOCKS5 credentials".into());
        }
    }
    let target = read_socks_target(stream)?;
    let upstream = match target.connect(redirect_host) {
        Ok(upstream) => upstream,
        Err(error) => {
            stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Err(error.into());
        }
    };
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    Ok(upstream)
}

fn http_handshake(
    stream: &mut TcpStream,
    credentials: Option<&(String, String)>,
    redirect_host: Option<&str>,
) -> Result<TcpStream, Box<dyn Error>> {
    let mut request = Vec::with_capacity(1024);
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == MAX_HTTP_HEADERS {
            return Err("HTTP CONNECT request headers are too large".into());
        }
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let request = String::from_utf8(request)?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().ok_or("missing HTTP request line")?;
    let mut fields = request_line.split_whitespace();
    if fields.next() != Some("CONNECT") {
        return Err("expected HTTP CONNECT".into());
    }
    let authority = fields.next().ok_or("missing CONNECT authority")?;
    let target: SocketAddr = authority.parse()?;
    if let Some((username, password)) = credentials {
        let expected = format!("Basic {}", BASE64.encode(format!("{username}:{password}")));
        let authorized = lines
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| {
                name.eq_ignore_ascii_case("Proxy-Authorization") && value.trim() == expected
            });
        if !authorized {
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")?;
            return Err("invalid HTTP proxy credentials".into());
        }
    }
    let upstream = if let Some(host) = redirect_host {
        TcpStream::connect((host, target.port()))?
    } else {
        TcpStream::connect(target)?
    };
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    Ok(upstream)
}

fn relay(mut client: TcpStream, mut upstream: TcpStream) -> Result<(), Box<dyn Error>> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let forward = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut client_reader, &mut upstream_writer)?;
        upstream_writer.shutdown(Shutdown::Write)?;
        Ok(copied)
    });
    std::io::copy(&mut upstream, &mut client)?;
    client.shutdown(Shutdown::Write)?;
    forward
        .join()
        .map_err(|_| "proxy relay worker panicked")??;
    Ok(())
}

fn handle(mut stream: TcpStream, mode: &Mode) -> Result<(), Box<dyn Error>> {
    let upstream = match mode {
        Mode::Socks5 {
            credentials,
            redirect_host,
        } => socks5_handshake(&mut stream, credentials.as_ref(), redirect_host.as_deref())?,
        Mode::Http {
            credentials,
            redirect_host,
        } => http_handshake(&mut stream, credentials.as_ref(), redirect_host.as_deref())?,
    };
    relay(stream, upstream)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let (protocol, port, redirect_host, credentials) = match args.as_slice() {
        [protocol, port] => (protocol.as_str(), port.parse()?, None, None),
        [protocol, port, redirect_host] => (
            protocol.as_str(),
            port.parse()?,
            Some(redirect_host.clone()),
            None,
        ),
        [protocol, port, redirect_host, username, password] => (
            protocol.as_str(),
            port.parse()?,
            Some(redirect_host.clone()),
            Some((username.clone(), password.clone())),
        ),
        _ => return Err(usage().into()),
    };
    let mode = match protocol {
        "socks5" => Mode::Socks5 {
            credentials,
            redirect_host,
        },
        "http" => Mode::Http {
            credentials,
            redirect_host,
        },
        _ => return Err(usage().into()),
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    println!("READY {}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for accepted in listener.incoming() {
        let stream = accepted?;
        let mode = mode.clone();
        thread::spawn(move || {
            if let Err(error) = handle(stream, &mode) {
                eprintln!("tcp-bench-proxy: {error}");
            }
        });
    }
    Ok(())
}
