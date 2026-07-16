use crate::ip::{Ipv4Packet, Ipv6Packet};
use crate::{PacketError, checksum};

pub const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    bytes: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse_ipv4(ip: Ipv4Packet<'a>, verify_checksum: bool) -> Result<Self, PacketError> {
        let datagram = Self::parse(ip.payload())?;
        // An all-zero IPv4 UDP checksum means the sender skipped it.
        if verify_checksum
            && datagram.checksum_field() != 0
            && checksum::ipv4_transport(
                ip.source(),
                ip.destination(),
                crate::ip::IPPROTO_UDP,
                datagram.bytes,
            ) != 0
        {
            return Err(PacketError::InvalidChecksum);
        }
        Ok(datagram)
    }

    pub fn parse_ipv6(ip: Ipv6Packet<'a>, verify_checksum: bool) -> Result<Self, PacketError> {
        let datagram = Self::parse(ip.payload())?;
        // RFC 8200: a zero UDP checksum is invalid over IPv6.
        if verify_checksum {
            if datagram.checksum_field() == 0 {
                return Err(PacketError::InvalidChecksum);
            }
            if checksum::ipv6_transport(
                ip.source(),
                ip.destination(),
                crate::ip::IPPROTO_UDP,
                datagram.bytes,
            ) != 0
            {
                return Err(PacketError::InvalidChecksum);
            }
        }
        Ok(datagram)
    }

    fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < UDP_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if length < UDP_HEADER_LEN || length > bytes.len() {
            return Err(PacketError::InvalidLength);
        }
        // The UDP length field is authoritative; IP-level padding after it
        // is dropped.
        Ok(Self {
            bytes: &bytes[..length],
        })
    }

    #[must_use]
    pub fn source_port(self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    #[must_use]
    pub fn destination_port(self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[UDP_HEADER_LEN..]
    }

    fn checksum_field(self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }
}

/// Writes a UDP header in front of `payload_len` bytes already placed at
/// `out[UDP_HEADER_LEN..]`. The checksum field is left zero; call one of
/// the `set_*_checksum` helpers afterwards.
pub fn write_header(
    out: &mut [u8],
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
) -> Result<usize, PacketError> {
    let length = UDP_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(PacketError::InvalidLength)?;
    if out.len() < length || length > usize::from(u16::MAX) {
        return Err(PacketError::InvalidLength);
    }
    out[..2].copy_from_slice(&source_port.to_be_bytes());
    out[2..4].copy_from_slice(&destination_port.to_be_bytes());
    out[4..6].copy_from_slice(&(length as u16).to_be_bytes());
    out[6..8].fill(0);
    Ok(UDP_HEADER_LEN)
}

pub fn set_ipv4_checksum(
    datagram: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
) -> Result<(), PacketError> {
    if datagram.len() < UDP_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    datagram[6..8].fill(0);
    let value = checksum::ipv4_transport(source, destination, crate::ip::IPPROTO_UDP, datagram);
    // A computed zero transmits as 0xffff so it is not read as "absent".
    let value = if value == 0 { 0xffff } else { value };
    datagram[6..8].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn set_ipv6_checksum(
    datagram: &mut [u8],
    source: [u8; 16],
    destination: [u8; 16],
) -> Result<(), PacketError> {
    if datagram.len() < UDP_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    datagram[6..8].fill(0);
    let value = checksum::ipv6_transport(source, destination, crate::ip::IPPROTO_UDP, datagram);
    let value = if value == 0 { 0xffff } else { value };
    datagram[6..8].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip;

    fn ipv4_packet(buffer: &mut [u8], payload_len: usize) -> Ipv4Packet<'_> {
        ip::write_ipv4_header(
            buffer,
            [192, 0, 2, 2],
            [192, 0, 2, 1],
            ip::IPPROTO_UDP,
            payload_len,
            0,
        )
        .unwrap();
        Ipv4Packet::parse(&buffer[..20 + payload_len]).unwrap()
    }

    #[test]
    fn round_trips_an_ipv4_datagram_with_checksum() {
        let mut buffer = [0u8; 64];
        buffer[20 + UDP_HEADER_LEN..20 + UDP_HEADER_LEN + 5].copy_from_slice(b"query");
        write_header(&mut buffer[20..], 4321, 53, 5).unwrap();
        let end = 20 + UDP_HEADER_LEN + 5;
        set_ipv4_checksum(&mut buffer[20..end], [192, 0, 2, 2], [192, 0, 2, 1]).unwrap();
        let packet = ipv4_packet(&mut buffer, UDP_HEADER_LEN + 5);
        let datagram = UdpDatagram::parse_ipv4(packet, true).unwrap();
        assert_eq!(datagram.source_port(), 4321);
        assert_eq!(datagram.destination_port(), 53);
        assert_eq!(datagram.payload(), b"query");
    }

    #[test]
    fn rejects_a_corrupted_ipv4_checksum() {
        let mut buffer = [0u8; 64];
        buffer[20 + UDP_HEADER_LEN..20 + UDP_HEADER_LEN + 5].copy_from_slice(b"query");
        write_header(&mut buffer[20..], 4321, 53, 5).unwrap();
        let end = 20 + UDP_HEADER_LEN + 5;
        set_ipv4_checksum(&mut buffer[20..end], [192, 0, 2, 2], [192, 0, 2, 1]).unwrap();
        buffer[20 + UDP_HEADER_LEN] ^= 0x01;
        let packet = ipv4_packet(&mut buffer, UDP_HEADER_LEN + 5);
        assert_eq!(
            UdpDatagram::parse_ipv4(packet, true).unwrap_err(),
            PacketError::InvalidChecksum
        );
    }

    #[test]
    fn accepts_an_absent_ipv4_checksum_but_not_ipv6() {
        let mut buffer = [0u8; 64];
        write_header(&mut buffer[20..], 4321, 53, 0).unwrap();
        let packet = ipv4_packet(&mut buffer, UDP_HEADER_LEN);
        assert!(UdpDatagram::parse_ipv4(packet, true).is_ok());

        let mut v6 = [0u8; 64];
        ip::write_ipv6_header(
            &mut v6,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ip::IPPROTO_UDP,
            UDP_HEADER_LEN,
        )
        .unwrap();
        write_header(&mut v6[40..], 4321, 53, 0).unwrap();
        let packet = Ipv6Packet::parse(&v6[..40 + UDP_HEADER_LEN]).unwrap();
        assert_eq!(
            UdpDatagram::parse_ipv6(packet, true).unwrap_err(),
            PacketError::InvalidChecksum
        );
    }

    #[test]
    fn truncated_length_field_is_rejected() {
        let mut buffer = [0u8; 64];
        write_header(&mut buffer[20..], 4321, 53, 5).unwrap();
        buffer[20 + 4..20 + 6].copy_from_slice(&100u16.to_be_bytes());
        let packet = ipv4_packet(&mut buffer, UDP_HEADER_LEN + 5);
        assert_eq!(
            UdpDatagram::parse_ipv4(packet, false).unwrap_err(),
            PacketError::InvalidLength
        );
    }
}
