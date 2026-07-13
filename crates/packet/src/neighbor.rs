use crate::{EtherType, MacAddress};
use crate::{PacketError, checksum, ethernet, ip};

pub const ARP_PACKET_LEN: usize = 28;

#[derive(Clone, Copy, Debug)]
pub struct ArpRequest {
    pub sender_mac: MacAddress,
    pub sender_ip: [u8; 4],
    pub target_ip: [u8; 4],
}

pub fn parse_arp_request(bytes: &[u8]) -> Result<ArpRequest, PacketError> {
    if bytes.len() < ARP_PACKET_LEN {
        return Err(PacketError::Truncated);
    }
    if bytes[0..8] != [0, 1, 0x08, 0, 6, 4, 0, 1] {
        return Err(PacketError::Unsupported);
    }
    Ok(ArpRequest {
        sender_mac: MacAddress(bytes[8..14].try_into().expect("validated ARP")),
        sender_ip: bytes[14..18].try_into().expect("validated ARP"),
        target_ip: bytes[24..28].try_into().expect("validated ARP"),
    })
}

pub fn write_arp_reply(
    out: &mut [u8],
    gateway_mac: MacAddress,
    gateway_ip: [u8; 4],
    request: ArpRequest,
) -> Result<usize, PacketError> {
    let len = ethernet::ETHERNET_HEADER_LEN + ARP_PACKET_LEN;
    if out.len() < len {
        return Err(PacketError::Truncated);
    }
    ethernet::write_header(out, request.sender_mac, gateway_mac, EtherType::Arp)?;
    let arp = &mut out[ethernet::ETHERNET_HEADER_LEN..len];
    arp[0..8].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
    arp[8..14].copy_from_slice(&gateway_mac.0);
    arp[14..18].copy_from_slice(&gateway_ip);
    arp[18..24].copy_from_slice(&request.sender_mac.0);
    arp[24..28].copy_from_slice(&request.sender_ip);
    Ok(len)
}

pub fn solicited_node_multicast(target: [u8; 16]) -> [u8; 16] {
    let mut address = [0; 16];
    address[0] = 0xff;
    address[1] = 0x02;
    address[11] = 0x01;
    address[12] = 0xff;
    address[13..16].copy_from_slice(&target[13..16]);
    address
}

pub fn parse_neighbor_solicitation(ipv6: crate::Ipv6Packet<'_>) -> Result<[u8; 16], PacketError> {
    if ipv6.next_header() != ip::IPPROTO_ICMPV6 {
        return Err(PacketError::ProtocolMismatch);
    }
    let payload = ipv6.payload();
    if payload.len() < 24 || payload[0] != 135 || payload[1] != 0 {
        return Err(PacketError::Unsupported);
    }
    if checksum::ipv6_transport(ipv6.source(), ipv6.destination(), 58, payload) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    Ok(payload[8..24].try_into().expect("validated NS"))
}

pub fn write_neighbor_advertisement(
    out: &mut [u8],
    gateway_mac: MacAddress,
    target_mac: MacAddress,
    gateway_ip: [u8; 16],
    target_ip: [u8; 16],
) -> Result<usize, PacketError> {
    const ICMP_LEN: usize = 32;
    let len = ethernet::ETHERNET_HEADER_LEN + 40 + ICMP_LEN;
    if out.len() < len {
        return Err(PacketError::Truncated);
    }
    ethernet::write_header(out, target_mac, gateway_mac, EtherType::Ipv6)?;
    let ip_offset = ethernet::ETHERNET_HEADER_LEN;
    ip::write_ipv6_header(
        &mut out[ip_offset..],
        gateway_ip,
        target_ip,
        ip::IPPROTO_ICMPV6,
        ICMP_LEN,
    )?;
    out[ip_offset + 7] = 255;
    let icmp_offset = ip_offset + 40;
    let icmp = &mut out[icmp_offset..icmp_offset + ICMP_LEN];
    icmp.fill(0);
    icmp[0] = 136;
    icmp[4] = 0x60;
    icmp[8..24].copy_from_slice(&gateway_ip);
    icmp[24] = 2;
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(&gateway_mac.0);
    let value = checksum::ipv6_transport(gateway_ip, target_ip, 58, icmp);
    icmp[2..4].copy_from_slice(&value.to_be_bytes());
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EthernetFrame, Ipv6Packet};

    #[test]
    fn advertisement_uses_required_hop_limit_and_checksum() {
        let gateway_ip: [u8; 16] = "fd79:6179:6174:6874::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let target_ip: [u8; 16] = "fd79:6179:6174:6874::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let mut frame = [0u8; 128];
        let length = write_neighbor_advertisement(
            &mut frame,
            MacAddress([2, 1, 2, 3, 4, 1]),
            MacAddress([2, 1, 2, 3, 4, 2]),
            gateway_ip,
            target_ip,
        )
        .unwrap();
        let ethernet = EthernetFrame::parse(&frame[..length]).unwrap();
        assert_eq!(ethernet.payload()[7], 255);
        let ipv6 = Ipv6Packet::parse(ethernet.payload()).unwrap();
        assert_eq!(
            checksum::ipv6_transport(gateway_ip, target_ip, 58, ipv6.payload()),
            0
        );
    }
}
