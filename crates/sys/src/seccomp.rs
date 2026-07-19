// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::io;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/seccomp_profiles.rs"));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    DataPlane,
    NamespaceInit,
    Supervisor,
}

impl Profile {
    fn syscalls(self) -> &'static [libc::c_long] {
        match self {
            Self::DataPlane => generated::DATA_PLANE,
            Self::NamespaceInit => generated::NAMESPACE_INIT,
            Self::Supervisor => generated::SUPERVISOR,
        }
    }
}

const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
const BPF_JUMP_EQUAL: u16 = 0x15;
const BPF_RETURN: u16 = 0x06;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_LOG: u32 = 0x7ffc_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

pub fn install(profile: Profile) -> io::Result<()> {
    let trace = cfg!(debug_assertions)
        && std::env::var_os("YAYATHT_SECCOMP_TRACE").is_some_and(|value| value == "1");
    let filter = build_filter(
        profile.syscalls(),
        if trace { RET_LOG } else { RET_KILL_PROCESS },
    )?;
    let length = u16::try_from(filter.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seccomp filter is too long"))?;
    let program = libc::sock_fprog {
        len: length,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: program points to a live cBPF instruction array and the caller
    // set NO_NEW_PRIVS before requesting a filter without synchronization.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            std::ptr::from_ref(&program),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn build_filter(
    syscalls: &[libc::c_long],
    default_action: u32,
) -> io::Result<Vec<libc::sock_filter>> {
    let mut filter = Vec::with_capacity(5 + syscalls.len() * 2);
    filter.push(statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_DATA_ARCH_OFFSET));
    filter.push(jump(BPF_JUMP_EQUAL, AUDIT_ARCH, 1, 0));
    filter.push(statement(BPF_RETURN, RET_KILL_PROCESS));
    filter.push(statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_DATA_NR_OFFSET));
    for &syscall in syscalls {
        let syscall = u32::try_from(syscall).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "negative syscall in seccomp profile",
            )
        })?;
        filter.push(jump(BPF_JUMP_EQUAL, syscall, 0, 1));
        filter.push(statement(BPF_RETURN, RET_ALLOW));
    }
    filter.push(statement(BPF_RETURN, default_action));
    Ok(filter)
}

const fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt,
        jf,
        k: value,
    }
}

#[cfg(test)]
mod tests {
    use super::{BPF_RETURN, Profile, RET_ALLOW, RET_KILL_PROCESS, build_filter};
    use std::collections::BTreeSet;

    #[test]
    fn generated_profiles_are_nonempty_and_unique() {
        for profile in [
            Profile::DataPlane,
            Profile::NamespaceInit,
            Profile::Supervisor,
        ] {
            let entries = profile.syscalls();
            assert!(!entries.is_empty());
            assert_eq!(entries.len(), entries.iter().collect::<BTreeSet<_>>().len());
        }
    }

    #[test]
    fn filter_guards_architecture_and_defaults_to_kill() {
        let filter = build_filter(&[libc::SYS_read, libc::SYS_write], RET_KILL_PROCESS).unwrap();
        assert_eq!(filter[2].code, BPF_RETURN);
        assert_eq!(filter[2].k, RET_KILL_PROCESS);
        assert_eq!(filter[5].k, RET_ALLOW);
        assert_eq!(filter.last().unwrap().k, RET_KILL_PROCESS);
    }
}
