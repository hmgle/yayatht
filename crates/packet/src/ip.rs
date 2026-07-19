// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use crate::{PacketError, checksum};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy)]
pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
    total_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 20 {
            return Err(PacketError::Truncated);
        }
        if bytes[0] >> 4 != 4 {
            return Err(PacketError::ProtocolMismatch);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return Err(PacketError::InvalidLength);
        }
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len || total_len > bytes.len() {
            return Err(PacketError::InvalidLength);
        }
        let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
        if fragment & 0x3fff != 0 {
            return Err(PacketError::Unsupported);
        }
        if checksum::checksum(&bytes[..header_len]) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        Ok(Self {
            bytes,
            header_len,
            total_len,
        })
    }

    #[must_use]
    pub fn source(self) -> [u8; 4] {
        self.bytes[12..16]
            .try_into()
            .expect("validated IPv4 header")
    }

    #[must_use]
    pub fn destination(self) -> [u8; 4] {
        self.bytes[16..20]
            .try_into()
            .expect("validated IPv4 header")
    }

    #[must_use]
    pub fn protocol(self) -> u8 {
        self.bytes[9]
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.header_len..self.total_len]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Packet<'a> {
    bytes: &'a [u8],
    payload_offset: usize,
    total_len: usize,
    next_header: u8,
}

impl<'a> Ipv6Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 40 {
            return Err(PacketError::Truncated);
        }
        if bytes[0] >> 4 != 6 {
            return Err(PacketError::ProtocolMismatch);
        }
        let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        let total_len = 40usize
            .checked_add(payload_len)
            .ok_or(PacketError::InvalidLength)?;
        if total_len > bytes.len() {
            return Err(PacketError::Truncated);
        }

        let mut next = bytes[6];
        let mut offset = 40usize;
        let mut headers = 0usize;
        let mut extension_bytes = 0usize;
        while matches!(next, 0 | 43 | 60 | 51) {
            if headers == 8 || offset + 2 > total_len {
                return Err(PacketError::Unsupported);
            }
            let current = next;
            next = bytes[offset];
            let length = if current == 51 {
                (usize::from(bytes[offset + 1]) + 2) * 4
            } else {
                (usize::from(bytes[offset + 1]) + 1) * 8
            };
            offset = offset
                .checked_add(length)
                .ok_or(PacketError::InvalidLength)?;
            extension_bytes += length;
            headers += 1;
            if extension_bytes > 256 || offset > total_len {
                return Err(PacketError::Unsupported);
            }
        }
        if next == 44 {
            return Err(PacketError::Unsupported);
        }
        Ok(Self {
            bytes,
            payload_offset: offset,
            total_len,
            next_header: next,
        })
    }

    #[must_use]
    pub fn source(self) -> [u8; 16] {
        self.bytes[8..24].try_into().expect("validated IPv6 header")
    }

    #[must_use]
    pub fn destination(self) -> [u8; 16] {
        self.bytes[24..40]
            .try_into()
            .expect("validated IPv6 header")
    }

    #[must_use]
    pub fn next_header(self) -> u8 {
        self.next_header
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.payload_offset..self.total_len]
    }
}

pub fn write_ipv4_header(
    out: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload_len: usize,
    identification: u16,
) -> Result<usize, PacketError> {
    let total_len = 20usize
        .checked_add(payload_len)
        .ok_or(PacketError::InvalidLength)?;
    if out.len() < 20 || total_len > usize::from(u16::MAX) {
        return Err(PacketError::InvalidLength);
    }
    out[..20].fill(0);
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[4..6].copy_from_slice(&identification.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    out[8] = 64;
    out[9] = protocol;
    out[12..16].copy_from_slice(&source);
    out[16..20].copy_from_slice(&destination);
    let value = checksum::checksum(&out[..20]);
    out[10..12].copy_from_slice(&value.to_be_bytes());
    Ok(20)
}

pub fn write_ipv6_header(
    out: &mut [u8],
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    payload_len: usize,
) -> Result<usize, PacketError> {
    if out.len() < 40 || payload_len > usize::from(u16::MAX) {
        return Err(PacketError::InvalidLength);
    }
    out[..40].fill(0);
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out[6] = next_header;
    out[7] = 64;
    out[8..24].copy_from_slice(&source);
    out[24..40].copy_from_slice(&destination);
    Ok(40)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ipv4_bad_checksum() {
        let mut packet = [0u8; 20];
        write_ipv4_header(&mut packet, [192, 0, 2, 1], [192, 0, 2, 2], 6, 0, 1).unwrap();
        packet[8] ^= 1;
        assert_eq!(
            Ipv4Packet::parse(&packet).unwrap_err(),
            PacketError::InvalidChecksum
        );
    }

    #[test]
    fn rejects_ipv6_fragment_header() {
        let mut packet = [0u8; 48];
        write_ipv6_header(&mut packet, [0; 16], [1; 16], 44, 8).unwrap();
        assert_eq!(
            Ipv6Packet::parse(&packet).unwrap_err(),
            PacketError::Unsupported
        );
    }
}
