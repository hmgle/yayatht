use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

fn socket_address(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroed sockaddr_storage is a valid base representation.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match address {
        SocketAddr::V4(address) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: storage is large and aligned enough for sockaddr_in.
            unsafe { std::ptr::write(std::ptr::from_mut(&mut storage).cast(), value) };
            (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(address) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: storage is large and aligned enough for sockaddr_in6.
            unsafe { std::ptr::write(std::ptr::from_mut(&mut storage).cast(), value) };
            (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

pub fn connect_nonblocking(address: SocketAddr) -> io::Result<(OwnedFd, bool)> {
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket arguments create a standard nonblocking TCP socket.
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let (storage, len) = socket_address(address);
    // SAFETY: storage contains the matching sockaddr variant.
    let result = unsafe { libc::connect(fd.as_raw_fd(), std::ptr::from_ref(&storage).cast(), len) };
    if result == 0 {
        return Ok((fd, true));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINPROGRESS) {
        Ok((fd, false))
    } else {
        Err(error)
    }
}

pub fn pending_error(fd: RawFd) -> io::Result<Option<i32>> {
    let mut error = 0i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: error and len are valid getsockopt output storage.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::from_mut(&mut error).cast(),
            std::ptr::from_mut(&mut len),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok((error != 0).then_some(error))
}

pub fn local_address(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: zeroed sockaddr_storage is valid writable getsockname storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: storage and len are valid getsockname output pointers.
    if unsafe {
        libc::getsockname(
            fd,
            std::ptr::from_mut(&mut storage).cast(),
            std::ptr::from_mut(&mut len),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    match i32::from(storage.ss_family) {
        libc::AF_INET if usize::try_from(len).unwrap_or(0) >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: getsockname reported AF_INET with enough initialized bytes.
            let address = unsafe {
                std::ptr::from_ref(&storage)
                    .cast::<libc::sockaddr_in>()
                    .read()
            };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if usize::try_from(len).unwrap_or(0) >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: getsockname reported AF_INET6 with enough initialized bytes.
            let address = unsafe {
                std::ptr::from_ref(&storage)
                    .cast::<libc::sockaddr_in6>()
                    .read()
            };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "getsockname returned an unsupported address",
        )),
    }
}

pub fn send_buffer_available(fd: RawFd) -> io::Result<usize> {
    let mut send_buffer = 0i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: send_buffer and len are valid getsockopt output storage.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::from_mut(&mut send_buffer).cast(),
            std::ptr::from_mut(&mut len),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    let mut queued = 0i32;
    // SAFETY: queued points to writable integer storage for TIOCOUTQ.
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ, std::ptr::from_mut(&mut queued)) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let usable = usize::try_from(send_buffer.max(0)).unwrap_or(0) / 2;
    let queued = usize::try_from(queued.max(0)).unwrap_or(usize::MAX);
    Ok(usable.saturating_sub(queued))
}

pub fn send(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: bytes is borrowed for the duration of send.
    let count = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

pub fn peek(fd: RawFd, out: &mut [u8]) -> io::Result<usize> {
    // SAFETY: out is writable for the duration of recv.
    let count = unsafe {
        libc::recv(
            fd,
            out.as_mut_ptr().cast(),
            out.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

pub fn discard(fd: RawFd, length: usize) -> io::Result<usize> {
    // SAFETY: Linux permits a null buffer with MSG_TRUNC for stream discard.
    let count = unsafe {
        libc::recv(
            fd,
            std::ptr::null_mut(),
            length,
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        )
    };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

pub fn shutdown_write(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is borrowed and SHUT_WR is a valid mode.
    if unsafe { libc::shutdown(fd, libc::SHUT_WR) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOTCONN) {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    #[test]
    fn local_address_matches_connected_socket() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(
            local_address(stream.as_raw_fd()).unwrap(),
            stream.local_addr().unwrap()
        );
    }
}
