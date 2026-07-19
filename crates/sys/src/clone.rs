// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub enum CloneResult {
    Parent { pid: libc::pid_t, pidfd: OwnedFd },
    Child,
}

pub fn clone_namespaced(flags: u64) -> io::Result<CloneResult> {
    let mut pidfd: RawFd = -1;
    let args = CloneArgs {
        flags: flags | u64::from(libc::CLONE_PIDFD as u32),
        pidfd: std::ptr::from_mut(&mut pidfd) as u64,
        exit_signal: u64::from(libc::SIGCHLD as u32),
        ..CloneArgs::default()
    };
    // SAFETY: clone_args follows clone3 UAPI. This is called before threads.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_ref(&args),
            size_of::<CloneArgs>(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        Ok(CloneResult::Child)
    } else {
        if pidfd < 0 {
            return Err(io::Error::other("clone3 did not return a pidfd"));
        }
        // SAFETY: clone3 returned ownership of a new pidfd in the parent.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        Ok(CloneResult::Parent {
            pid: result as libc::pid_t,
            pidfd,
        })
    }
}

pub fn pidfd_send_signal(pidfd: RawFd, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd is borrowed and siginfo is intentionally null.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit is required on post-clone error paths.
    unsafe { libc::_exit(code) }
}
