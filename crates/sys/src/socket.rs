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

/// Zero-timeout probe for an in-flight nonblocking connect: true once the
/// socket is writable or carries a pending error. A loopback handshake
/// usually completes inside the kernel before the caller returns to its
/// event loop, so this catches it without a sleep/wake round trip.
pub fn poll_writable_now(fd: RawFd) -> io::Result<bool> {
    let mut probe = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: probe points to one valid pollfd and the timeout is zero.
    let ready = unsafe { libc::poll(std::ptr::from_mut(&mut probe), 1, 0) };
    if ready == -1 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(ready > 0 && probe.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0)
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

pub fn recv(fd: RawFd, out: &mut [u8]) -> io::Result<usize> {
    // SAFETY: out is writable for the duration of recv.
    let count = unsafe { libc::recv(fd, out.as_mut_ptr().cast(), out.len(), libc::MSG_DONTWAIT) };
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

/// Summary of one socket error-queue drain.
#[derive(Debug, Default, Clone, Copy)]
pub struct TxTimestampDrain {
    /// Messages that carried a transmit-acknowledgment timestamp.
    pub acknowledgments: usize,
    /// Messages whose extended error did not originate from timestamping.
    pub foreign_errors: usize,
}

/// Requests a software timestamp on the socket error queue each time the
/// peer acknowledges submitted bytes. `OPT_TSONLY` keeps packet payload out
/// of the queued messages.
pub fn enable_tx_ack_timestamps(fd: RawFd) -> io::Result<()> {
    let flags: libc::c_uint = libc::SOF_TIMESTAMPING_TX_ACK
        | libc::SOF_TIMESTAMPING_SOFTWARE
        | libc::SOF_TIMESTAMPING_OPT_TSONLY;
    // SAFETY: flags points to a valid c_uint SO_TIMESTAMPING option value.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            std::ptr::from_ref(&flags).cast(),
            size_of::<libc::c_uint>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drains every queued error-queue message so level-triggered `EPOLLERR`
/// clears, and classifies each one. Timestamp messages only signal that
/// acknowledged bytes advanced; callers read the amount from `TCP_INFO`.
pub fn drain_tx_timestamps(fd: RawFd) -> io::Result<TxTimestampDrain> {
    const BATCH: usize = 16;
    let mut drain = TxTimestampDrain::default();
    // OPT_TSONLY leaves the data part empty; control holds the timestamp
    // block plus one extended-error header per message.
    let mut controls = [[0u8; 512]; BATCH];
    loop {
        // SAFETY: zeroed mmsghdrs are valid when only control storage is set.
        let mut messages = unsafe { std::mem::zeroed::<[libc::mmsghdr; BATCH]>() };
        for (message, control) in messages.iter_mut().zip(controls.iter_mut()) {
            message.msg_hdr.msg_control = control.as_mut_ptr().cast();
            message.msg_hdr.msg_controllen = control.len() as _;
        }
        // SAFETY: messages references writable storage for the duration of
        // recvmmsg.
        let received = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                BATCH as libc::c_uint,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if received == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(drain);
            }
            return Err(error);
        }
        for message in &messages[..received as usize] {
            let mut timestamped = false;
            let mut foreign = false;
            // SAFETY: recvmmsg initialized the control region it reports.
            let mut cursor = unsafe { libc::CMSG_FIRSTHDR(&message.msg_hdr) };
            while !cursor.is_null() {
                // SAFETY: cursor is a valid cmsghdr within the control region.
                let header = unsafe { &*cursor };
                match (header.cmsg_level, header.cmsg_type) {
                    (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => timestamped = true,
                    (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                        // SAFETY: the kernel stores a sock_extended_err payload
                        // for RECVERR control messages.
                        let extended =
                            unsafe { &*libc::CMSG_DATA(cursor).cast::<libc::sock_extended_err>() };
                        if extended.ee_origin != libc::SO_EE_ORIGIN_TIMESTAMPING {
                            foreign = true;
                        }
                    }
                    _ => {}
                }
                // SAFETY: message and cursor remain valid for CMSG_NXTHDR.
                cursor = unsafe { libc::CMSG_NXTHDR(&message.msg_hdr, cursor) };
            }
            if timestamped && !foreign {
                drain.acknowledgments += 1;
            }
            if foreign {
                drain.foreign_errors += 1;
            }
        }
        // A partial batch means the queue emptied; anything enqueued after
        // that instant re-raises the level-triggered EPOLLERR, exactly as
        // it would after a terminal-EAGAIN read.
        if (received as usize) < BATCH {
            return Ok(drain);
        }
    }
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
    fn writable_probe_catches_a_loopback_connect_without_events() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (socket, connected) =
            connect_nonblocking(listener.local_addr().unwrap(), 256 << 10, 256 << 10).unwrap();
        // The loopback handshake completes inside the kernel almost
        // immediately; bound the wait instead of assuming the very first
        // probe wins the race.
        let mut ready = connected;
        for _ in 0..1000 {
            if ready {
                break;
            }
            ready = poll_writable_now(socket.as_raw_fd()).unwrap();
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
        assert!(ready, "loopback connect never became writable");
        assert_eq!(pending_error(socket.as_raw_fd()).unwrap(), None);
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
    fn tx_ack_timestamps_surface_on_the_error_queue() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        enable_tx_ack_timestamps(sender.as_raw_fd()).unwrap();
        sender.write_all(b"ping").unwrap();
        let mut out = [0u8; 4];
        receiver.read_exact(&mut out).unwrap();
        // The loopback ACK is prompt but asynchronous; poll briefly.
        let mut acknowledgments = 0;
        for _ in 0..200 {
            let drain = drain_tx_timestamps(sender.as_raw_fd()).unwrap();
            assert_eq!(drain.foreign_errors, 0);
            acknowledgments += drain.acknowledgments;
            if acknowledgments > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(acknowledgments > 0, "no TX ACK timestamp was queued");
    }
}
