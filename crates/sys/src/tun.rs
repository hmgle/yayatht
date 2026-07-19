// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const TUNSETIFF: libc::Ioctl = 0x4004_54ca as libc::Ioctl;
const TUNSETOFFLOAD: libc::Ioctl = 0x4004_54d0 as libc::Ioctl;
const TUN_F_CSUM: libc::c_ulong = 0x01;
const TUN_F_TSO4: libc::c_ulong = 0x02;
const TUN_F_TSO6: libc::c_ulong = 0x04;

pub const DEFAULT_TAP_MTU: u32 = 32_000;
pub const MIN_TAP_MTU: u32 = 1_280;
pub const MAX_TAP_MTU: u32 = 65_520;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

/// Creates one namespace-side TAP queue. `multi_queue` makes repeated calls
/// with the same name attach independent queues to one interface. `offload`
/// negotiates
/// `IFF_VNET_HDR`, prefixing every read and write on the returned fd with
/// a `virtio_net_hdr`, and enables checksum plus TCP segmentation
/// offload: the namespace kernel may then hand over `NEEDS_CSUM` frames
/// and TSO super-frames up to 64 KiB, and accepts the same from the data
/// plane. UDP offloads (USO) wait for UDP support. The Linux 6.6
/// baseline guarantees these feature bits, so a rejected negotiation is
/// an error rather than a degraded mode.
pub fn create_tap(name: &str, offload: bool, multi_queue: bool) -> io::Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    if name.as_bytes().len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name is too long",
        ));
    }
    let path = c"/dev/net/tun";
    // SAFETY: path is NUL-terminated and flags require no mode argument.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw was returned by open and ownership is transferred here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let flags = tap_flags(offload, multi_queue);
    let mut request = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: flags as libc::c_short,
        padding: [0; 22],
    };
    for (target, source) in request.name.iter_mut().zip(name.as_bytes()) {
        *target = *source as libc::c_char;
    }
    // SAFETY: request matches Linux struct ifreq size/layout for TUNSETIFF.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &request) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if offload {
        // SAFETY: TUNSETOFFLOAD passes the feature mask by value.
        if unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                TUNSETOFFLOAD,
                TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(fd)
}

const fn tap_flags(offload: bool, multi_queue: bool) -> libc::c_int {
    let mut flags = libc::IFF_TAP | libc::IFF_NO_PI;
    if offload {
        flags |= libc::IFF_VNET_HDR;
    }
    if multi_queue {
        flags |= libc::IFF_MULTI_QUEUE;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::tap_flags;

    #[test]
    fn multiqueue_flag_is_opt_in() {
        let single = tap_flags(true, false);
        let multi = tap_flags(true, true);
        assert_eq!(single & libc::IFF_MULTI_QUEUE, 0);
        assert_ne!(multi & libc::IFF_MULTI_QUEUE, 0);
        assert_ne!(multi & libc::IFF_VNET_HDR, 0);
    }
}
