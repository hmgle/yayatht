use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Bind-mounts `source` over `/etc/resolv.conf` in the caller's private
/// mount namespace. The kernel resolves a symlinked target, so a
/// systemd-resolved style indirection is covered as long as the final
/// path exists.
pub fn bind_resolv_conf(source: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source contains NUL"))?;
    // SAFETY: both paths are NUL-terminated and the bind mount affects
    // only the caller's private mount namespace.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            c"/etc/resolv.conf".as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } == -1
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "bind mount over /etc/resolv.conf failed ({error}); pass --dns off if the namespace image has no resolv.conf"
            ),
        ));
    }
    Ok(())
}

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
