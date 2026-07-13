use linux_raw_sys::net::tcp_info;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::RawFd;

#[derive(Clone, Copy, Debug)]
pub struct TcpInfo {
    pub bytes_acked: u64,
    pub send_window: u32,
    pub unacked_segments: u32,
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
    // SAFETY: getsockopt initialized the UAPI structure on supported kernels.
    let info = unsafe { info.assume_init() };
    Ok(TcpInfo {
        bytes_acked: info.tcpi_bytes_acked,
        send_window: info.tcpi_snd_wnd,
        unacked_segments: info.tcpi_unacked,
    })
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
