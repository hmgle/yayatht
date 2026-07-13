use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub struct SignalFd {
    fd: OwnedFd,
}

impl SignalFd {
    pub fn block(signals: &[i32]) -> io::Result<Self> {
        // SAFETY: zeroed sigset_t is initialized immediately with sigemptyset.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: set points to valid sigset_t storage.
        unsafe {
            libc::sigemptyset(std::ptr::from_mut(&mut set));
            for signal in signals {
                libc::sigaddset(std::ptr::from_mut(&mut set), *signal);
            }
            if libc::pthread_sigmask(
                libc::SIG_BLOCK,
                std::ptr::from_ref(&set),
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: set is initialized and signalfd creates a new descriptor.
        let raw = unsafe {
            libc::signalfd(
                -1,
                std::ptr::from_ref(&set),
                libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly owned descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn read(&self) -> io::Result<Option<i32>> {
        // SAFETY: zeroed signalfd_siginfo is valid output storage.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        // SAFETY: info is writable for a complete signalfd record.
        let count = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut info).cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some(info.ssi_signo as i32))
    }
}
