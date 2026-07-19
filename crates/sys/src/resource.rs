// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::io;

pub const DATAPLANE_FD_HEADROOM: u64 = 32;

pub fn dataplane_nofile_limit(
    max_tcp_flows: usize,
    max_udp_flows: usize,
    max_udp_associations: usize,
) -> io::Result<u64> {
    let tcp = u64::try_from(max_tcp_flows)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TCP flow limit exceeds u64"))?;
    let udp = u64::try_from(max_udp_flows)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UDP flow limit exceeds u64"))?;
    let associations = u64::try_from(max_udp_associations).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP association limit exceeds u64",
        )
    })?;
    tcp.checked_add(udp)
        .and_then(|value| {
            associations
                .checked_mul(2)
                .and_then(|extra| value.checked_add(extra))
        })
        .and_then(|value| value.checked_add(DATAPLANE_FD_HEADROOM))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fd budget overflow"))
}

pub fn ensure_nofile_capacity(required: u64) -> io::Result<()> {
    let limit = nofile_limit()?;
    if limit.rlim_max < required {
        return Err(io::Error::other(format!(
            "RLIMIT_NOFILE hard limit {} is below required data-plane budget {required}",
            limit.rlim_max
        )));
    }
    Ok(())
}

pub fn set_nofile_limit(limit: u64) -> io::Result<()> {
    let value = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // SAFETY: value is a valid RLIMIT_NOFILE limit structure.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, std::ptr::from_ref(&value)) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn disable_core_dumps() -> io::Result<()> {
    let value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: value is a valid RLIMIT_CORE limit structure.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, std::ptr::from_ref(&value)) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn nofile_limit() -> io::Result<libc::rlimit> {
    // SAFETY: zeroed rlimit is valid writable getrlimit storage.
    let mut value = unsafe { std::mem::zeroed::<libc::rlimit>() };
    // SAFETY: value points to writable RLIMIT_NOFILE output storage.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::from_mut(&mut value)) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_phase2_budget_includes_udp_association_pairs() {
        assert_eq!(dataplane_nofile_limit(4096, 8192, 2048).unwrap(), 16416);
    }
}
