use std::ffi::CString;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitStatus {
    Exited(i32),
    Signaled(i32),
    StillRunning,
    NoChildren,
}

pub fn fork_exec(command: &[CString]) -> io::Result<libc::pid_t> {
    if command.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
    }
    // SAFETY: fork is called in the single-threaded namespace init process.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: child initializes an empty mask and its own process group.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(std::ptr::from_mut(&mut mask));
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                std::ptr::from_ref(&mask),
                std::ptr::null_mut(),
            );
            libc::setpgid(0, 0);
            let mut argv: Vec<*const libc::c_char> =
                command.iter().map(|item| item.as_ptr()).collect();
            argv.push(std::ptr::null());
            libc::execvp(command[0].as_ptr(), argv.as_ptr());
            let error = io::Error::last_os_error();
            libc::_exit(if error.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
    }
    Ok(pid)
}

pub fn wait_pid(pid: libc::pid_t, nohang: bool) -> io::Result<WaitStatus> {
    let mut status = 0;
    let flags = if nohang { libc::WNOHANG } else { 0 };
    // SAFETY: status is valid output storage and pid follows waitpid rules.
    let result = unsafe { libc::waitpid(pid, std::ptr::from_mut(&mut status), flags) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(WaitStatus::NoChildren);
        }
        return Err(error);
    }
    if result == 0 {
        return Ok(WaitStatus::StillRunning);
    }
    if libc::WIFEXITED(status) {
        Ok(WaitStatus::Exited(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(WaitStatus::Signaled(libc::WTERMSIG(status)))
    } else {
        Ok(WaitStatus::StillRunning)
    }
}

pub fn wait_any_nohang() -> io::Result<Option<(libc::pid_t, WaitStatus)>> {
    let mut status = 0;
    // SAFETY: status is valid output storage and -1 selects any child.
    let result = unsafe { libc::waitpid(-1, std::ptr::from_mut(&mut status), libc::WNOHANG) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(None);
        }
        return Err(error);
    }
    if result == 0 {
        return Ok(Some((-1, WaitStatus::StillRunning)));
    }
    let status = if libc::WIFEXITED(status) {
        WaitStatus::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        WaitStatus::Signaled(libc::WTERMSIG(status))
    } else {
        WaitStatus::StillRunning
    };
    Ok(Some((result, status)))
}

pub fn signal_process_group(pid: libc::pid_t, signal: i32) -> io::Result<()> {
    // SAFETY: negative pid selects the process group created for target.
    if unsafe { libc::kill(-pid, signal) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}
