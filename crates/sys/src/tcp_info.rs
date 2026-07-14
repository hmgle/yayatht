use linux_raw_sys::net::tcp_info;
use std::io;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::fd::RawFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpInfo {
    pub bytes_acked: Option<u64>,
    pub send_window: Option<u32>,
    pub unacked_segments: Option<u32>,
    pub returned_len: usize,
}

pub fn get(fd: RawFd) -> io::Result<TcpInfo> {
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
    Ok(decode(info, len as usize))
}

fn decode(info: tcp_info, returned_len: usize) -> TcpInfo {
    TcpInfo {
        bytes_acked: field_available::<u64>(returned_len, offset_of!(tcp_info, tcpi_bytes_acked))
            .then_some(info.tcpi_bytes_acked),
        send_window: field_available::<u32>(returned_len, offset_of!(tcp_info, tcpi_snd_wnd))
            .then_some(info.tcpi_snd_wnd),
        unacked_segments: field_available::<u32>(returned_len, offset_of!(tcp_info, tcpi_unacked))
            .then_some(info.tcpi_unacked),
        returned_len,
    }
}

fn field_available<T>(returned_len: usize, offset: usize) -> bool {
    returned_len >= offset.saturating_add(size_of::<T>())
}

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

pub fn probe_peek_offset(fd: RawFd) -> io::Result<bool> {
    match set_peek_offset(fd, 0) {
        Ok(()) => Ok(true),
        Err(error)
            if error.raw_os_error().is_some_and(|code| {
                code == libc::ENOPROTOOPT
                    || code == libc::EOPNOTSUPP
                    || code == libc::EINVAL
                    || code == libc::EPERM
            }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
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
    fn tcp_info_fields_follow_returned_prefix_length() {
        // SAFETY: tcp_info contains only integer UAPI fields and is valid when zeroed.
        let mut info = unsafe { std::mem::zeroed::<tcp_info>() };
        info.tcpi_unacked = 3;
        info.tcpi_bytes_acked = 17;
        info.tcpi_snd_wnd = 29;

        let before_bytes = offset_of!(tcp_info, tcpi_bytes_acked);
        let through_bytes = before_bytes + size_of::<u64>();
        let through_window = offset_of!(tcp_info, tcpi_snd_wnd) + size_of::<u32>();

        let old = decode(info, before_bytes);
        assert_eq!(old.unacked_segments, Some(3));
        assert_eq!(old.bytes_acked, None);
        assert_eq!(old.send_window, None);

        let bytes = decode(info, through_bytes);
        assert_eq!(bytes.bytes_acked, Some(17));
        assert_eq!(bytes.send_window, None);

        let current = decode(info, through_window);
        assert_eq!(current.bytes_acked, Some(17));
        assert_eq!(current.send_window, Some(29));
    }
}
