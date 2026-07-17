use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Replaces the caller's root with an empty, private tmpfs. The caller must
/// own a private mount namespace and still hold CAP_SYS_ADMIN there.
pub fn isolate_filesystem() -> io::Result<()> {
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
    // Mount directly over /tmp in this private namespace so pivoting leaves
    // no directory behind in the host-visible filesystem.
    // SAFETY: all strings are static and NUL-terminated.
    if unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"size=64k,mode=0700".as_ptr().cast(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the path is a child of the new root mount and mode is valid.
    if unsafe { libc::mkdir(c"/tmp/.old_root".as_ptr(), 0o700) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: /tmp is a mount point and .old_root is beneath it.
    if unsafe { libc::chdir(c"/tmp".as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both paths are relative to /tmp and satisfy pivot_root rules.
    if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old_root".as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the pivot succeeded and the new root is available at /.
    if unsafe { libc::chdir(c"/".as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: detach the old filesystem tree from the private namespace.
    if unsafe { libc::umount2(c"/.old_root".as_ptr(), libc::MNT_DETACH) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the detached mount point is now an empty directory on tmpfs.
    if unsafe { libc::rmdir(c"/.old_root".as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

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
