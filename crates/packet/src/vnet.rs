// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

//! Legacy `virtio_net_hdr` prefix carried on every TAP frame when the
//! device is opened with `IFF_VNET_HDR` (Linux `linux/virtio_net.h`).
//! The TUN interface exchanges the header in native endianness.

use crate::PacketError;

pub const VNET_HEADER_LEN: usize = 10;

/// Checksum starts at `csum_start` and the complement goes to
/// `csum_start + csum_offset`; only a pseudo-header sum is filled in.
pub const FLAG_NEEDS_CSUM: u8 = 1;
/// The checksum was already verified by the sending kernel.
pub const FLAG_DATA_VALID: u8 = 2;

pub const GSO_NONE: u8 = 0;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_TCPV6: u8 = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VnetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < VNET_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        Ok(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_ne_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_ne_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_ne_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_ne_bytes([bytes[8], bytes[9]]),
        })
    }

    pub fn write(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < VNET_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        Ok(())
    }

    /// A frame that carries no offload state: complete checksums and no
    /// segmentation. `DATA_VALID` only asserts the checksum was verified,
    /// so the frame body still parses like a plain frame.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.gso_type == GSO_NONE && (self.flags & !FLAG_DATA_VALID) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_survives_a_write_parse_round_trip() {
        let header = VnetHeader {
            flags: FLAG_NEEDS_CSUM,
            gso_type: GSO_TCPV4,
            hdr_len: 54,
            gso_size: 1460,
            csum_start: 34,
            csum_offset: 16,
        };
        let mut bytes = [0u8; VNET_HEADER_LEN];
        header.write(&mut bytes).unwrap();
        assert_eq!(VnetHeader::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn short_buffers_are_rejected() {
        let bytes = [0u8; VNET_HEADER_LEN - 1];
        assert_eq!(VnetHeader::parse(&bytes), Err(PacketError::Truncated));
        let mut out = [0u8; VNET_HEADER_LEN - 1];
        assert_eq!(
            VnetHeader::default().write(&mut out),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn plain_frames_allow_only_verified_checksums() {
        assert!(VnetHeader::default().is_plain());
        assert!(
            VnetHeader {
                flags: FLAG_DATA_VALID,
                ..VnetHeader::default()
            }
            .is_plain()
        );
        assert!(
            !VnetHeader {
                flags: FLAG_NEEDS_CSUM,
                ..VnetHeader::default()
            }
            .is_plain()
        );
        assert!(
            !VnetHeader {
                gso_type: GSO_TCPV6,
                ..VnetHeader::default()
            }
            .is_plain()
        );
    }
}
