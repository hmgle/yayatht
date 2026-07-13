use base64::Engine as _;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

const MAX_CREDENTIAL_COMPONENT: usize = u8::MAX as usize;
const MAX_HTTP_HEADER: usize = 8 * 1024;

#[derive(Clone)]
pub struct Credentials(Arc<Secret>);

struct Secret {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl Credentials {
    pub fn new(username: Vec<u8>, password: Vec<u8>) -> Result<Self, Error> {
        if username.is_empty()
            || password.is_empty()
            || username.len() > MAX_CREDENTIAL_COMPONENT
            || password.len() > MAX_CREDENTIAL_COMPONENT
        {
            return Err(Error::InvalidCredentials);
        }
        Ok(Self(Arc::new(Secret { username, password })))
    }

    fn username(&self) -> &[u8] {
        &self.0.username
    }

    fn password(&self) -> &[u8] {
        &self.0.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credentials(REDACTED)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("proxy username and password must each contain 1 to 255 bytes")]
    InvalidCredentials,
    #[error("proxy handshake was advanced in an invalid state")]
    InvalidState,
    #[error("proxy response uses an invalid protocol encoding: {0}")]
    InvalidResponse(&'static str),
    #[error("SOCKS5 proxy selected unsupported authentication method {0:#04x}")]
    UnsupportedSocksMethod(u8),
    #[error("SOCKS5 proxy requires username/password authentication")]
    SocksAuthenticationRequired,
    #[error("SOCKS5 username/password authentication failed")]
    SocksAuthenticationFailed,
    #[error("SOCKS5 CONNECT failed with reply code {0:#04x}")]
    SocksConnectFailed(u8),
    #[error("HTTP CONNECT response headers exceed 8192 bytes")]
    HttpHeaderTooLarge,
    #[error("HTTP CONNECT failed with status {0}")]
    HttpConnectFailed(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    SocksGreetingWrite,
    SocksMethodRead,
    SocksAuthWrite,
    SocksAuthRead,
    SocksConnectWrite,
    SocksConnectRead,
    HttpWrite,
    HttpRead,
    Complete,
}

pub struct Handshake {
    state: State,
    target: SocketAddr,
    credentials: Option<Credentials>,
    output: Vec<u8>,
    output_offset: usize,
}

impl Handshake {
    pub fn new(protocol: Protocol, target: SocketAddr, credentials: Option<Credentials>) -> Self {
        let (state, output) = match protocol {
            Protocol::Socks5 => (
                State::SocksGreetingWrite,
                socks_greeting(credentials.is_some()),
            ),
            Protocol::HttpConnect => (
                State::HttpWrite,
                http_connect_request(target, credentials.as_ref()),
            ),
        };
        Self {
            state,
            target,
            credentials,
            output,
            output_offset: 0,
        }
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output[self.output_offset..]
    }

    #[must_use]
    pub const fn wants_input(&self) -> bool {
        matches!(
            self.state,
            State::SocksMethodRead
                | State::SocksAuthRead
                | State::SocksConnectRead
                | State::HttpRead
        )
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }

    pub fn advance_output(&mut self, length: usize) -> Result<(), Error> {
        if length > self.output().len() || self.output().is_empty() {
            return Err(Error::InvalidState);
        }
        self.output_offset += length;
        if self.output_offset != self.output.len() {
            return Ok(());
        }
        self.clear_output();
        self.state = match self.state {
            State::SocksGreetingWrite => State::SocksMethodRead,
            State::SocksAuthWrite => State::SocksAuthRead,
            State::SocksConnectWrite => State::SocksConnectRead,
            State::HttpWrite => State::HttpRead,
            _ => return Err(Error::InvalidState),
        };
        Ok(())
    }

    pub fn receive(&mut self, input: &[u8]) -> Result<usize, Error> {
        match self.state {
            State::SocksMethodRead => self.receive_socks_method(input),
            State::SocksAuthRead => self.receive_socks_auth(input),
            State::SocksConnectRead => self.receive_socks_connect(input),
            State::HttpRead => self.receive_http(input),
            _ => Err(Error::InvalidState),
        }
    }

    fn receive_socks_method(&mut self, input: &[u8]) -> Result<usize, Error> {
        if input.len() < 2 {
            return Ok(0);
        }
        if input[0] != 5 {
            return Err(Error::InvalidResponse("SOCKS5 method version"));
        }
        match input[1] {
            0 => {
                self.set_output(socks_connect_request(self.target));
                self.state = State::SocksConnectWrite;
            }
            2 => {
                let credentials = self
                    .credentials
                    .as_ref()
                    .ok_or(Error::SocksAuthenticationRequired)?;
                self.set_output(socks_auth_request(credentials));
                self.state = State::SocksAuthWrite;
            }
            method => return Err(Error::UnsupportedSocksMethod(method)),
        }
        Ok(2)
    }

    fn receive_socks_auth(&mut self, input: &[u8]) -> Result<usize, Error> {
        if input.len() < 2 {
            return Ok(0);
        }
        if input[0] != 1 {
            return Err(Error::InvalidResponse("SOCKS5 authentication version"));
        }
        if input[1] != 0 {
            return Err(Error::SocksAuthenticationFailed);
        }
        self.set_output(socks_connect_request(self.target));
        self.state = State::SocksConnectWrite;
        Ok(2)
    }

    fn receive_socks_connect(&mut self, input: &[u8]) -> Result<usize, Error> {
        if input.len() < 4 {
            return Ok(0);
        }
        if input[0] != 5 || input[2] != 0 {
            return Err(Error::InvalidResponse("SOCKS5 CONNECT header"));
        }
        let length = match input[3] {
            1 => 10,
            4 => 22,
            3 if input.len() < 5 => return Ok(0),
            3 => 7usize.saturating_add(usize::from(input[4])),
            _ => return Err(Error::InvalidResponse("SOCKS5 address type")),
        };
        if input.len() < length {
            return Ok(0);
        }
        if input[1] != 0 {
            return Err(Error::SocksConnectFailed(input[1]));
        }
        self.state = State::Complete;
        self.credentials = None;
        Ok(length)
    }

    fn receive_http(&mut self, input: &[u8]) -> Result<usize, Error> {
        let Some(end) = input
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        else {
            if input.len() >= MAX_HTTP_HEADER {
                return Err(Error::HttpHeaderTooLarge);
            }
            return Ok(0);
        };
        if end > MAX_HTTP_HEADER {
            return Err(Error::HttpHeaderTooLarge);
        }
        let line_end = input[..end]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(Error::InvalidResponse("HTTP status line"))?;
        let line = std::str::from_utf8(&input[..line_end])
            .map_err(|_| Error::InvalidResponse("HTTP status encoding"))?;
        let mut fields = line.split_ascii_whitespace();
        let version = fields
            .next()
            .ok_or(Error::InvalidResponse("HTTP version"))?;
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return Err(Error::InvalidResponse("HTTP version"));
        }
        let status = fields
            .next()
            .ok_or(Error::InvalidResponse("HTTP status"))?
            .parse::<u16>()
            .map_err(|_| Error::InvalidResponse("HTTP status"))?;
        if !(200..300).contains(&status) {
            return Err(Error::HttpConnectFailed(status));
        }
        self.state = State::Complete;
        self.credentials = None;
        Ok(end)
    }

    fn set_output(&mut self, output: Vec<u8>) {
        self.clear_output();
        self.output = output;
    }

    fn clear_output(&mut self) {
        self.output.zeroize();
        self.output.clear();
        self.output_offset = 0;
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("state", &self.state)
            .field("target", &self.target)
            .field("credentials", &self.credentials)
            .field("output", &"REDACTED")
            .finish()
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.output.zeroize();
    }
}

fn socks_greeting(has_credentials: bool) -> Vec<u8> {
    if has_credentials {
        vec![5, 2, 0, 2]
    } else {
        vec![5, 1, 0]
    }
}

fn socks_auth_request(credentials: &Credentials) -> Vec<u8> {
    let username = credentials.username();
    let password = credentials.password();
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[1, username.len() as u8]);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    request
}

fn socks_connect_request(target: SocketAddr) -> Vec<u8> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[5, 1, 0]);
    match target {
        SocketAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    request
}

fn http_connect_request(target: SocketAddr, credentials: Option<&Credentials>) -> Vec<u8> {
    use std::fmt::Write as _;

    let authority = match target {
        SocketAddr::V4(address) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    };
    let mut request = String::with_capacity(256);
    write!(
        request,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    )
    .expect("writing to String cannot fail");
    if let Some(credentials) = credentials {
        let mut raw =
            Vec::with_capacity(credentials.username().len() + credentials.password().len() + 1);
        raw.extend_from_slice(credentials.username());
        raw.push(b':');
        raw.extend_from_slice(credentials.password());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
        raw.zeroize();
        write!(request, "Proxy-Authorization: Basic {encoded}\r\n")
            .expect("writing to String cannot fail");
    }
    request.push_str("\r\n");
    request.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_output(handshake: &mut Handshake) -> Vec<u8> {
        let output = handshake.output().to_vec();
        let split = output.len() / 2;
        if split > 0 {
            handshake.advance_output(split).unwrap();
        }
        handshake
            .advance_output(output.len().saturating_sub(split))
            .unwrap();
        output
    }

    #[test]
    fn socks5_no_auth_ipv4_connect() {
        let target = "203.0.113.7:443".parse().unwrap();
        let mut handshake = Handshake::new(Protocol::Socks5, target, None);
        assert_eq!(drain_output(&mut handshake), [5, 1, 0]);
        assert!(handshake.wants_input());
        assert_eq!(handshake.receive(&[5]).unwrap(), 0);
        assert_eq!(handshake.receive(&[5, 0, 99]).unwrap(), 2);
        assert_eq!(
            drain_output(&mut handshake),
            [5, 1, 0, 1, 203, 0, 113, 7, 1, 187]
        );
        assert_eq!(
            handshake.receive(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1, 42]),
            Ok(10)
        );
        assert!(handshake.is_complete());
    }

    #[test]
    fn socks5_username_password_ipv6_connect() {
        let credentials = Credentials::new(b"user".to_vec(), b"pass".to_vec()).unwrap();
        let target = "[2001:db8::7]:53".parse().unwrap();
        let mut handshake = Handshake::new(Protocol::Socks5, target, Some(credentials));
        assert_eq!(drain_output(&mut handshake), [5, 2, 0, 2]);
        assert_eq!(handshake.receive(&[5, 2]), Ok(2));
        assert_eq!(
            drain_output(&mut handshake),
            [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
        );
        assert_eq!(handshake.receive(&[1, 0]), Ok(2));
        let request = drain_output(&mut handshake);
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &request[4..20],
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&request[20..], &53u16.to_be_bytes());
        assert_eq!(handshake.receive(&[5, 0, 0, 3, 1, b'x', 0, 0]), Ok(8));
        assert!(handshake.is_complete());
    }

    #[test]
    fn socks5_reports_auth_and_connect_failures() {
        let mut handshake = Handshake::new(Protocol::Socks5, "192.0.2.1:80".parse().unwrap(), None);
        drain_output(&mut handshake);
        assert_eq!(
            handshake.receive(&[5, 2]),
            Err(Error::SocksAuthenticationRequired)
        );

        let mut handshake = Handshake::new(Protocol::Socks5, "192.0.2.1:80".parse().unwrap(), None);
        drain_output(&mut handshake);
        handshake.receive(&[5, 0]).unwrap();
        drain_output(&mut handshake);
        assert_eq!(
            handshake.receive(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]),
            Err(Error::SocksConnectFailed(5))
        );
    }

    #[test]
    fn http_connect_basic_auth_and_tail_preservation() {
        let credentials = Credentials::new(b"Aladdin".to_vec(), b"open sesame".to_vec()).unwrap();
        let mut handshake = Handshake::new(
            Protocol::HttpConnect,
            "[2001:db8::1]:443".parse().unwrap(),
            Some(credentials),
        );
        let request = String::from_utf8(drain_output(&mut handshake)).unwrap();
        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"));
        let response = b"HTTP/1.1 200 Connection Established\r\nX-Test: yes\r\n\r\ntarget data";
        let consumed = handshake.receive(response).unwrap();
        assert_eq!(&response[consumed..], b"target data");
        assert!(handshake.is_complete());
    }

    #[test]
    fn http_connect_rejects_failure_and_oversized_headers() {
        let target = "192.0.2.1:80".parse().unwrap();
        let mut handshake = Handshake::new(Protocol::HttpConnect, target, None);
        drain_output(&mut handshake);
        assert_eq!(
            handshake.receive(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Err(Error::HttpConnectFailed(407))
        );

        let mut handshake = Handshake::new(Protocol::HttpConnect, target, None);
        drain_output(&mut handshake);
        assert_eq!(
            handshake.receive(&vec![b'x'; MAX_HTTP_HEADER]),
            Err(Error::HttpHeaderTooLarge)
        );
    }
}
