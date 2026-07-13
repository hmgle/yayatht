use std::io;

pub fn mount_private_proc() -> io::Result<()> {
    // SAFETY: null source/fs/data are valid for a recursive private remount.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this affects only the caller's private mount namespace.
    if unsafe { libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(error);
        }
    }
    // SAFETY: source, target and filesystem strings are NUL-terminated.
    if unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
