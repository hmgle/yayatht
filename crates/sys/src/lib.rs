#![cfg(target_os = "linux")]

pub mod caps;
pub mod clone;
pub mod control;
pub mod fdpass;
pub mod mount;
pub mod netlink;
pub mod process;
pub mod reactor;
pub mod resource;
pub mod seccomp;
pub mod signal;
pub mod socket;
pub mod tcp_info;
pub mod tun;

use std::io;
use std::os::fd::RawFd;

pub fn set_nonblocking(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFL does not use a third argument.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if current == -1 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        current | libc::O_NONBLOCK
    } else {
        current & !libc::O_NONBLOCK
    };
    // SAFETY: flags came from F_GETFL with only O_NONBLOCK changed.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
