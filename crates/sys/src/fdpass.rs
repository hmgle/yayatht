use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to storage for two descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair initialized both descriptors and transfers ownership.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn send_packet(socket: RawFd, packet: &[u8]) -> io::Result<()> {
    // SAFETY: packet is borrowed for the duration of send.
    let written = unsafe {
        libc::send(
            socket,
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written == -1 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short SOCK_SEQPACKET send",
        ));
    }
    Ok(())
}

pub fn recv_packet(socket: RawFd, out: &mut [u8]) -> io::Result<usize> {
    // SAFETY: out is writable for the duration of recv.
    let read = unsafe { libc::recv(socket, out.as_mut_ptr().cast(), out.len(), 0) };
    if read == -1 {
        return Err(io::Error::last_os_error());
    }
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control channel closed",
        ));
    }
    Ok(read as usize)
}

pub fn send_fd(socket: RawFd, fd: RawFd, payload: &[u8]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: CMSG_SPACE is a pure size calculation.
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; control_len];
    // SAFETY: zero is a valid initial msghdr representation.
    let mut message: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    message.msg_iov = std::ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    #[allow(clippy::useless_conversion)]
    let control_length = control
        .len()
        .try_into()
        .expect("control buffer length fits");
    message.msg_controllen = control_length;
    // SAFETY: msghdr owns a sufficiently sized control buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::from_mut(&mut message));
        if cmsg.is_null() {
            return Err(io::Error::other("unable to construct SCM_RIGHTS"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        let descriptor_len = libc::CMSG_LEN(size_of::<RawFd>() as u32)
            .try_into()
            .expect("descriptor control length fits");
        (*cmsg).cmsg_len = descriptor_len;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        message.msg_controllen = (*cmsg).cmsg_len;
        if libc::sendmsg(socket, std::ptr::from_ref(&message), libc::MSG_NOSIGNAL) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn recv_fd(socket: RawFd, payload: &mut [u8]) -> io::Result<(usize, OwnedFd)> {
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: CMSG_SPACE is a pure size calculation.
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; control_len];
    // SAFETY: zero is a valid initial msghdr representation.
    let mut message: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    message.msg_iov = std::ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    #[allow(clippy::useless_conversion)]
    let control_length = control
        .len()
        .try_into()
        .expect("control buffer length fits");
    message.msg_controllen = control_length;
    // SAFETY: msghdr points to valid payload and control buffers.
    let read = unsafe {
        libc::recvmsg(
            socket,
            std::ptr::from_mut(&mut message),
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if read <= 0 {
        return Err(if read == 0 {
            io::Error::new(io::ErrorKind::UnexpectedEof, "fd channel closed")
        } else {
            io::Error::last_os_error()
        });
    }
    // SAFETY: the kernel initialized the control buffer.
    let raw = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::from_mut(&mut message));
        let descriptor_len = libc::CMSG_LEN(size_of::<RawFd>() as u32)
            .try_into()
            .expect("descriptor control length fits");
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len < descriptor_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing SCM_RIGHTS",
            ));
        }
        std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>())
    };
    if raw < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid received fd",
        ));
    }
    // SAFETY: SCM_RIGHTS transfers ownership of this descriptor.
    Ok((read as usize, unsafe { OwnedFd::from_raw_fd(raw) }))
}
