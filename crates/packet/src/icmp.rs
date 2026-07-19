// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use crate::{PacketError, checksum, ip, udp};
use std::net::SocketAddr;

const ICMP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV4_DESTINATION_UNREACHABLE: u8 = 3;
const IPV4_FRAGMENTATION_NEEDED: u8 = 4;
const IPV6_DESTINATION_UNREACHABLE: u8 = 1;
const IPV6_PACKET_TOO_BIG: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpError {
    DestinationUnreachable { code: u8 },
    PacketTooBig { mtu: u32 },
}

/// Writes a complete IPv4 or IPv6 ICMP error packet for a namespace-originated
/// UDP datagram. The quote carries the original IP and UDP headers plus the
/// supplied payload prefix; IPv4 quotes are capped at the RFC minimum 8 bytes.
pub fn write_udp_error(
    out: &mut [u8],
    source: SocketAddr,
    destination: SocketAddr,
    payload_prefix: &[u8],
    original_payload_len: usize,
    error: UdpError,
) -> Result<usize, PacketError> {
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => write_ipv4_udp_error(
            out,
            source.ip().octets(),
            destination.ip().octets(),
            source.port(),
            destination.port(),
            &payload_prefix[..payload_prefix.len().min(8)],
            original_payload_len,
            error,
        ),
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => write_ipv6_udp_error(
            out,
            source.ip().octets(),
            destination.ip().octets(),
            source.port(),
            destination.port(),
            payload_prefix,
            original_payload_len,
            error,
        ),
        _ => Err(PacketError::ProtocolMismatch),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_ipv4_udp_error(
    out: &mut [u8],
    original_source: [u8; 4],
    original_destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload_prefix: &[u8],
    original_payload_len: usize,
    error: UdpError,
) -> Result<usize, PacketError> {
    let quote_len = IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + payload_prefix.len();
    let icmp_len = ICMP_HEADER_LEN + quote_len;
    let total_len = IPV4_HEADER_LEN + icmp_len;
    if out.len() < total_len {
        return Err(PacketError::Truncated);
    }
    let udp_len = udp::UDP_HEADER_LEN
        .checked_add(original_payload_len)
        .ok_or(PacketError::InvalidLength)?;
    if udp_len > usize::from(u16::MAX) {
        return Err(PacketError::InvalidLength);
    }
    ip::write_ipv4_header(
        out,
        original_destination,
        original_source,
        ip::IPPROTO_ICMP,
        icmp_len,
        0,
    )?;
    let icmp = &mut out[IPV4_HEADER_LEN..total_len];
    icmp.fill(0);
    match error {
        UdpError::DestinationUnreachable { code } => {
            icmp[0] = IPV4_DESTINATION_UNREACHABLE;
            icmp[1] = code;
        }
        UdpError::PacketTooBig { mtu } => {
            icmp[0] = IPV4_DESTINATION_UNREACHABLE;
            icmp[1] = IPV4_FRAGMENTATION_NEEDED;
            let mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
            icmp[6..8].copy_from_slice(&mtu.to_be_bytes());
        }
    }
    let quoted_ip = ICMP_HEADER_LEN;
    ip::write_ipv4_header(
        &mut icmp[quoted_ip..],
        original_source,
        original_destination,
        ip::IPPROTO_UDP,
        udp_len,
        0,
    )?;
    let quoted_udp = quoted_ip + IPV4_HEADER_LEN;
    write_quoted_udp_header(
        &mut icmp[quoted_udp..quoted_udp + udp::UDP_HEADER_LEN],
        source_port,
        destination_port,
        udp_len,
    );
    icmp[quoted_udp + udp::UDP_HEADER_LEN..].copy_from_slice(payload_prefix);
    let value = checksum::checksum(icmp);
    icmp[2..4].copy_from_slice(&value.to_be_bytes());
    Ok(total_len)
}

#[allow(clippy::too_many_arguments)]
fn write_ipv6_udp_error(
    out: &mut [u8],
    original_source: [u8; 16],
    original_destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    payload_prefix: &[u8],
    original_payload_len: usize,
    error: UdpError,
) -> Result<usize, PacketError> {
    let quote_len = IPV6_HEADER_LEN + udp::UDP_HEADER_LEN + payload_prefix.len();
    let icmp_len = ICMP_HEADER_LEN + quote_len;
    let total_len = IPV6_HEADER_LEN + icmp_len;
    if out.len() < total_len {
        return Err(PacketError::Truncated);
    }
    let udp_len = udp::UDP_HEADER_LEN
        .checked_add(original_payload_len)
        .ok_or(PacketError::InvalidLength)?;
    if udp_len > usize::from(u16::MAX) {
        return Err(PacketError::InvalidLength);
    }
    ip::write_ipv6_header(
        out,
        original_destination,
        original_source,
        ip::IPPROTO_ICMPV6,
        icmp_len,
    )?;
    let icmp = &mut out[IPV6_HEADER_LEN..total_len];
    icmp.fill(0);
    match error {
        UdpError::DestinationUnreachable { code } => {
            icmp[0] = IPV6_DESTINATION_UNREACHABLE;
            icmp[1] = code;
        }
        UdpError::PacketTooBig { mtu } => {
            icmp[0] = IPV6_PACKET_TOO_BIG;
            icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
        }
    }
    let quoted_ip = ICMP_HEADER_LEN;
    ip::write_ipv6_header(
        &mut icmp[quoted_ip..],
        original_source,
        original_destination,
        ip::IPPROTO_UDP,
        udp_len,
    )?;
    let quoted_udp = quoted_ip + IPV6_HEADER_LEN;
    write_quoted_udp_header(
        &mut icmp[quoted_udp..quoted_udp + udp::UDP_HEADER_LEN],
        source_port,
        destination_port,
        udp_len,
    );
    icmp[quoted_udp + udp::UDP_HEADER_LEN..].copy_from_slice(payload_prefix);
    let value = checksum::ipv6_transport(
        original_destination,
        original_source,
        ip::IPPROTO_ICMPV6,
        icmp,
    );
    icmp[2..4].copy_from_slice(&value.to_be_bytes());
    Ok(total_len)
}

fn write_quoted_udp_header(out: &mut [u8], source: u16, destination: u16, length: usize) {
    out[..2].copy_from_slice(&source.to_be_bytes());
    out[2..4].copy_from_slice(&destination.to_be_bytes());
    out[4..6].copy_from_slice(&(length as u16).to_be_bytes());
    out[6..8].fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{Ipv4Packet, Ipv6Packet};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn writes_ipv4_port_unreachable_with_udp_quote() {
        let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 40000));
        let destination = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 9));
        let mut bytes = [0u8; 128];
        let length = write_udp_error(
            &mut bytes,
            source,
            destination,
            b"abcdefghijk",
            11,
            UdpError::DestinationUnreachable { code: 3 },
        )
        .unwrap();
        let packet = Ipv4Packet::parse(&bytes[..length]).unwrap();
        assert_eq!(packet.source(), [198, 51, 100, 7]);
        assert_eq!(packet.destination(), [192, 0, 2, 2]);
        assert_eq!(packet.protocol(), ip::IPPROTO_ICMP);
        let icmp = packet.payload();
        assert_eq!(&icmp[..2], &[3, 3]);
        assert_eq!(checksum::checksum(icmp), 0);
        let quote = &icmp[8..];
        assert_eq!(&quote[12..16], &[192, 0, 2, 2]);
        assert_eq!(&quote[20..22], &40000u16.to_be_bytes());
        assert_eq!(&quote[22..24], &9u16.to_be_bytes());
        assert_eq!(&quote[28..], b"abcdefgh");
    }

    #[test]
    fn writes_ipv6_packet_too_big_with_valid_checksum() {
        let source = SocketAddr::V6(SocketAddrV6::new(
            "fd79:6179:6174:6874::2".parse::<Ipv6Addr>().unwrap(),
            50000,
            0,
            0,
        ));
        let destination = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::7".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            0,
        ));
        let mut bytes = [0u8; 256];
        let length = write_udp_error(
            &mut bytes,
            source,
            destination,
            b"payload-prefix",
            1400,
            UdpError::PacketTooBig { mtu: 1280 },
        )
        .unwrap();
        let packet = Ipv6Packet::parse(&bytes[..length]).unwrap();
        assert_eq!(packet.next_header(), ip::IPPROTO_ICMPV6);
        let icmp = packet.payload();
        assert_eq!(icmp[0], 2);
        assert_eq!(&icmp[4..8], &1280u32.to_be_bytes());
        assert_eq!(
            checksum::ipv6_transport(
                packet.source(),
                packet.destination(),
                ip::IPPROTO_ICMPV6,
                icmp,
            ),
            0
        );
        let quote = &icmp[8..];
        assert_eq!(
            &quote[8..24],
            &"fd79:6179:6174:6874::2"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&quote[40..42], &50000u16.to_be_bytes());
        assert_eq!(&quote[48..], b"payload-prefix");
    }

    #[test]
    fn rejects_mixed_address_families() {
        let mut bytes = [0u8; 128];
        assert_eq!(
            write_udp_error(
                &mut bytes,
                "192.0.2.2:1".parse().unwrap(),
                "[2001:db8::1]:2".parse().unwrap(),
                &[],
                0,
                UdpError::DestinationUnreachable { code: 3 },
            ),
            Err(PacketError::ProtocolMismatch)
        );
    }
}
