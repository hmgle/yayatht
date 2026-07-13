use std::io;

pub fn set_child_subreaper() -> io::Result<()> {
    // SAFETY: prctl is called with the documented integer-only operation.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl is called with the documented integer-only operation.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_parent_death_signal(signal: i32) -> io::Result<()> {
    // SAFETY: prctl is called with the documented integer-only operation.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, signal, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn drop_all_capabilities() -> io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: pointers refer to correctly sized Linux capset v3 structures.
    let result =
        unsafe { libc::syscall(libc::SYS_capset, std::ptr::from_ref(&header), data.as_ptr()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    for capability in 0..=63 {
        // SAFETY: PR_CAPBSET_DROP accepts an integer capability index.
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::EPERM)) {
                return Err(error);
            }
        }
    }
    Ok(())
}
