use crate::{PacketError, checksum, ip::Ipv4Packet, ip::Ipv6Packet};

pub const TCP_MIN_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

impl<'a> TcpSegment<'a> {
    pub fn parse_ipv4(ip: Ipv4Packet<'a>) -> Result<Self, PacketError> {
        if ip.protocol() != crate::ip::IPPROTO_TCP {
            return Err(PacketError::ProtocolMismatch);
        }
        let payload = ip.payload();
        if checksum::ipv4_transport(ip.source(), ip.destination(), 6, payload) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        Self::parse(payload)
    }

    pub fn parse_ipv6(ip: Ipv6Packet<'a>) -> Result<Self, PacketError> {
        if ip.next_header() != crate::ip::IPPROTO_TCP {
            return Err(PacketError::ProtocolMismatch);
        }
        let payload = ip.payload();
        if checksum::ipv6_transport(ip.source(), ip.destination(), 6, payload) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        Self::parse(payload)
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < TCP_MIN_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let header_len = usize::from(bytes[12] >> 4) * 4;
        if header_len < TCP_MIN_HEADER_LEN || header_len > bytes.len() {
            return Err(PacketError::InvalidLength);
        }
        Ok(Self { bytes, header_len })
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
    pub fn sequence(self) -> u32 {
        u32::from_be_bytes(self.bytes[4..8].try_into().expect("validated TCP header"))
    }

    #[must_use]
    pub fn acknowledgment(self) -> u32 {
        u32::from_be_bytes(self.bytes[8..12].try_into().expect("validated TCP header"))
    }

    #[must_use]
    pub fn flags(self) -> TcpFlags {
        let value = self.bytes[13];
        TcpFlags {
            fin: value & 0x01 != 0,
            syn: value & 0x02 != 0,
            rst: value & 0x04 != 0,
            psh: value & 0x08 != 0,
            ack: value & 0x10 != 0,
        }
    }

    #[must_use]
    pub fn window(self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    #[must_use]
    pub fn mss(self) -> Option<u16> {
        let mut options = &self.bytes[TCP_MIN_HEADER_LEN..self.header_len];
        while let Some((&kind, rest)) = options.split_first() {
            match kind {
                0 => break,
                1 => options = rest,
                _ => {
                    let (&len, tail) = rest.split_first()?;
                    let len = usize::from(len);
                    if len < 2 || len - 2 > tail.len() {
                        return None;
                    }
                    if kind == 2 && len == 4 {
                        return Some(u16::from_be_bytes([tail[0], tail[1]]));
                    }
                    options = &tail[len - 2..];
                }
            }
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpHeaderSpec {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
}

pub fn write_header(out: &mut [u8], spec: TcpHeaderSpec) -> Result<usize, PacketError> {
    let header_len = if spec.mss.is_some() { 24 } else { 20 };
    if out.len() < header_len {
        return Err(PacketError::Truncated);
    }
    out[..header_len].fill(0);
    out[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
    out[2..4].copy_from_slice(&spec.destination_port.to_be_bytes());
    out[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
    out[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
    out[12] = (header_len as u8 / 4) << 4;
    out[13] = u8::from(spec.flags.fin)
        | (u8::from(spec.flags.syn) << 1)
        | (u8::from(spec.flags.rst) << 2)
        | (u8::from(spec.flags.psh) << 3)
        | (u8::from(spec.flags.ack) << 4);
    out[14..16].copy_from_slice(&spec.window.to_be_bytes());
    if let Some(mss) = spec.mss {
        out[20] = 2;
        out[21] = 4;
        out[22..24].copy_from_slice(&mss.to_be_bytes());
    }
    Ok(header_len)
}

pub fn set_ipv4_checksum(
    tcp: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
) -> Result<(), PacketError> {
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    tcp[16..18].fill(0);
    let value = checksum::ipv4_transport(source, destination, 6, tcp);
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn set_ipv6_checksum(
    tcp: &mut [u8],
    source: [u8; 16],
    destination: [u8; 16],
) -> Result<(), PacketError> {
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    tcp[16..18].fill(0);
    let value = checksum::ipv6_transport(source, destination, 6, tcp);
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
    Ok(())
}
