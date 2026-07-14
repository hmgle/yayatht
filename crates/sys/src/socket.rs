use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const PEEK_DISCARD_CHUNK: usize = 4096;
const PEEK_FALLBACK_MAX_OFFSET: usize = u16::MAX as usize;
const PEEK_FALLBACK_IOVECS: usize = 17;

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

pub fn connect_nonblocking(
    address: SocketAddr,
    receive_buffer_bytes: usize,
    send_buffer_bytes: usize,
) -> io::Result<(OwnedFd, bool)> {
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
    set_buffer_quota(fd.as_raw_fd(), libc::SO_RCVBUF, receive_buffer_bytes)?;
    set_buffer_quota(fd.as_raw_fd(), libc::SO_SNDBUF, send_buffer_bytes)?;
    set_nodelay(fd.as_raw_fd())?;
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

fn set_nodelay(fd: RawFd) -> io::Result<()> {
    let enabled = 1i32;
    // SAFETY: enabled points to a valid c_int TCP_NODELAY option value.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            std::ptr::from_ref(&enabled).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_buffer_quota(fd: RawFd, option: i32, quota: usize) -> io::Result<()> {
    let requested = i32::try_from(quota / 2).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket buffer quota exceeds i32",
        )
    })?;
    // SAFETY: requested points to a valid c_int socket option value.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&requested).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    let actual = socket_buffer_size(fd, option)?;
    if actual > quota {
        return Err(io::Error::other(format!(
            "kernel socket buffer {actual} exceeds configured quota {quota}"
        )));
    }
    Ok(())
}

fn socket_buffer_size(fd: RawFd, option: i32) -> io::Result<usize> {
    let mut value = 0i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: value and len are valid getsockopt output storage.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast(),
            std::ptr::from_mut(&mut len),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(value.max(0)).unwrap_or(usize::MAX))
}

pub fn socket_buffer_sizes(fd: RawFd) -> io::Result<(usize, usize)> {
    Ok((
        socket_buffer_size(fd, libc::SO_RCVBUF)?,
        socket_buffer_size(fd, libc::SO_SNDBUF)?,
    ))
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
    let usable = usize::try_from(send_buffer.max(0)).unwrap_or(0) / 2;
    Ok(usable.saturating_sub(send_queue_bytes(fd)?))
}

pub fn send_queue_bytes(fd: RawFd) -> io::Result<usize> {
    let mut queued = 0i32;
    // SAFETY: queued points to writable integer storage for TIOCOUTQ.
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ, std::ptr::from_mut(&mut queued)) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(queued.max(0)).unwrap_or(usize::MAX))
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

pub fn peek_with_offset(fd: RawFd, offset: usize, out: &mut [u8]) -> io::Result<usize> {
    if offset > PEEK_FALLBACK_MAX_OFFSET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket peek offset exceeds bounded fallback",
        ));
    }
    if offset == 0 {
        return peek(fd, out);
    }
    let mut discard = [0u8; PEEK_DISCARD_CHUNK];
    let mut iovecs = std::array::from_fn::<libc::iovec, PEEK_FALLBACK_IOVECS, _>(|_| libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    });
    let mut remaining = offset;
    let mut count = 0usize;
    while remaining > 0 {
        let length = remaining.min(discard.len());
        iovecs[count] = libc::iovec {
            iov_base: discard.as_mut_ptr().cast(),
            iov_len: length,
        };
        count += 1;
        remaining -= length;
    }
    iovecs[count] = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: out.len(),
    };
    count += 1;
    // SAFETY: zeroed msghdr is valid when only msg_iov and msg_iovlen are set.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = iovecs.as_mut_ptr();
    message.msg_iovlen = count;
    // SAFETY: every iovec references writable storage for the duration of recvmsg.
    // The discard iovecs intentionally overlap because their contents are ignored.
    let received = unsafe {
        libc::recvmsg(
            fd,
            std::ptr::from_mut(&mut message),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if received == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((received as usize).saturating_sub(offset))
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
    use std::io::{Read, Write};
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

    #[test]
    fn forwarding_socket_disables_nagle() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (socket, _) =
            connect_nonblocking(listener.local_addr().unwrap(), 256 << 10, 256 << 10).unwrap();
        let mut enabled = 0i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: enabled and length are valid getsockopt output storage.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    std::ptr::from_mut(&mut enabled).cast(),
                    std::ptr::from_mut(&mut length),
                )
            },
            0
        );
        assert_eq!(enabled, 1);
    }

    #[test]
    fn iovec_peek_skips_a_bounded_prefix_without_consuming_data() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        sender.write_all(b"abcdefgh").unwrap();

        let mut out = [0u8; 3];
        assert_eq!(
            peek_with_offset(receiver.as_raw_fd(), 2, &mut out).unwrap(),
            3
        );
        assert_eq!(&out, b"cde");

        let mut all = [0u8; 8];
        receiver.read_exact(&mut all).unwrap();
        assert_eq!(&all, b"abcdefgh");
    }

    #[test]
    fn iovec_peek_handles_offsets_across_discard_chunks() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        let bytes = (0..60 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        sender.write_all(&bytes).unwrap();

        let offset = 48 * 1024;
        let mut out = [0u8; 1460];
        assert_eq!(
            peek_with_offset(receiver.as_raw_fd(), offset, &mut out).unwrap(),
            out.len()
        );
        assert_eq!(&out, &bytes[offset..offset + out.len()]);

        let mut prefix = [0u8; 8];
        receiver.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &bytes[..prefix.len()]);
    }
}
