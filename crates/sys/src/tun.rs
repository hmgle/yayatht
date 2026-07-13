use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const TUNSETIFF: libc::Ioctl = 0x4004_54ca as libc::Ioctl;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

pub fn create_tap(name: &str) -> io::Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    if name.as_bytes().len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name is too long",
        ));
    }
    let path = c"/dev/net/tun";
    // SAFETY: path is NUL-terminated and flags require no mode argument.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw was returned by open and ownership is transferred here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
        padding: [0; 22],
    };
    for (target, source) in request.name.iter_mut().zip(name.as_bytes()) {
        *target = *source as libc::c_char;
    }
    // SAFETY: request matches Linux struct ifreq size/layout for TUNSETIFF.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &request) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
