use linux_raw_sys::net::tcp_info;
use std::io;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::fd::RawFd;

/// Reads the upstream socket's cumulative acknowledged byte count. The
/// Linux 6.6 baseline guarantees `tcpi_bytes_acked`; a kernel that returns
/// a `TCP_INFO` structure too short to contain it is unsupported.
pub fn bytes_acked(fd: RawFd) -> io::Result<u64> {
    let mut info = MaybeUninit::<tcp_info>::zeroed();
    let mut len = size_of::<tcp_info>() as libc::socklen_t;
    // SAFETY: info points to writable tcp_info storage and len describes it.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr().cast(),
            std::ptr::from_mut(&mut len),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the entire structure was zeroed before getsockopt initialized its
    // supported prefix, so every integer field has a valid representation.
    let info = unsafe { info.assume_init() };
    decode_bytes_acked(&info, len as usize)
}

fn decode_bytes_acked(info: &tcp_info, returned_len: usize) -> io::Result<u64> {
    let required = offset_of!(tcp_info, tcpi_bytes_acked) + size_of::<u64>();
    if returned_len < required {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel returned a TCP_INFO without tcpi_bytes_acked; Linux 6.6+ is required",
        ));
    }
    Ok(info.tcpi_bytes_acked)
}

/// Enables `SO_PEEK_OFF` tracking on the socket so `MSG_PEEK` reads follow
/// the configured offset. The Linux 6.6 baseline guarantees the option.
pub fn set_peek_offset(fd: RawFd, offset: i32) -> io::Result<()> {
    // SAFETY: offset points to a valid c_int option value.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEEK_OFF,
            std::ptr::from_ref(&offset).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_window_clamp(fd: RawFd, window: u32) -> io::Result<()> {
    // SAFETY: window points to a valid u32 TCP_WINDOW_CLAMP option value.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_WINDOW_CLAMP,
            std::ptr::from_ref(&window).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_acked_requires_the_full_field() {
        // SAFETY: tcp_info contains only integer UAPI fields and is valid when zeroed.
        let mut info = unsafe { std::mem::zeroed::<tcp_info>() };
        info.tcpi_bytes_acked = 17;

        let through_bytes = offset_of!(tcp_info, tcpi_bytes_acked) + size_of::<u64>();
        assert_eq!(decode_bytes_acked(&info, through_bytes).unwrap(), 17);

        let truncated = decode_bytes_acked(&info, through_bytes - 1).unwrap_err();
        assert_eq!(truncated.kind(), io::ErrorKind::Unsupported);
    }
}
