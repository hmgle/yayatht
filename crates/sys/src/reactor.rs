use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub const READABLE: u32 = libc::EPOLLIN as u32;
pub const WRITABLE: u32 = libc::EPOLLOUT as u32;
pub const ERROR: u32 = libc::EPOLLERR as u32;
pub const HANGUP: u32 = libc::EPOLLHUP as u32;
pub const READ_HANGUP: u32 = libc::EPOLLRDHUP as u32;

#[derive(Clone, Copy, Debug, Default)]
pub struct Event {
    pub events: u32,
    pub token: u64,
}

pub struct Epoll {
    fd: OwnedFd,
}

impl Epoll {
    pub fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 accepts the CLOEXEC flag.
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly owned descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }

    pub fn add(&self, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_ADD, fd, events, token)
    }

    pub fn modify(&self, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_MOD, fd, events, token)
    }

    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        // SAFETY: fd is borrowed; DEL ignores the event pointer.
        if unsafe {
            libc::epoll_ctl(
                self.fd.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                fd,
                std::ptr::null_mut(),
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn control(&self, operation: i32, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        let mut event = libc::epoll_event { events, u64: token };
        // SAFETY: event points to a valid epoll_event for the duration of call.
        if unsafe {
            libc::epoll_ctl(
                self.fd.as_raw_fd(),
                operation,
                fd,
                std::ptr::from_mut(&mut event),
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn wait(&self, out: &mut [Event], timeout: Option<Duration>) -> io::Result<usize> {
        let timeout = timeout.map_or(-1, |value| {
            i32::try_from(value.as_millis()).unwrap_or(i32::MAX)
        });
        let mut raw = vec![libc::epoll_event { events: 0, u64: 0 }; out.len()];
        // SAFETY: raw is writable storage for maxevents entries.
        let count = unsafe {
            libc::epoll_wait(
                self.fd.as_raw_fd(),
                raw.as_mut_ptr(),
                raw.len() as i32,
                timeout,
            )
        };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(error);
        }
        for (target, source) in out.iter_mut().zip(&raw[..count as usize]) {
            *target = Event {
                events: source.events,
                token: source.u64,
            };
        }
        Ok(count as usize)
    }
}

pub struct TimerFd {
    fd: OwnedFd,
}

impl TimerFd {
    pub fn periodic(interval: Duration) -> io::Result<Self> {
        // SAFETY: timerfd_create arguments are valid.
        let raw = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let timer = Self { fd };
        timer.set_interval(interval)?;
        Ok(timer)
    }

    /// Rearms the periodic interval; the next expiration is one full new
    /// interval away.
    pub fn set_interval(&self, interval: Duration) -> io::Result<()> {
        let seconds = interval.as_secs().try_into().unwrap_or(i64::MAX);
        let nanos = interval.subsec_nanos() as libc::c_long;
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: seconds,
                tv_nsec: nanos,
            },
            it_value: libc::timespec {
                tv_sec: seconds,
                tv_nsec: nanos,
            },
        };
        // SAFETY: spec is a valid periodic timer description.
        if unsafe {
            libc::timerfd_settime(
                self.fd.as_raw_fd(),
                0,
                std::ptr::from_ref(&spec),
                std::ptr::null_mut(),
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn consume(&self) -> io::Result<u64> {
        let mut value = 0u64;
        // SAFETY: value is writable storage for a timerfd counter.
        let count = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut value).cast(),
                size_of::<u64>(),
            )
        };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(error);
        }
        Ok(value)
    }
}

pub fn read(fd: RawFd, out: &mut [u8]) -> io::Result<usize> {
    // SAFETY: out is writable for the duration of read.
    let count = unsafe { libc::read(fd, out.as_mut_ptr().cast(), out.len()) };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

pub fn write(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: bytes is borrowed for the duration of write.
    let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}
