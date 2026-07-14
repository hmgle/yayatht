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
        self.find_option(2, 4)
            .map(|value| u16::from_be_bytes([value[0], value[1]]))
    }

    #[must_use]
    pub fn window_scale(self) -> Option<u8> {
        self.find_option(3, 3).map(|value| value[0])
    }

    fn find_option(self, wanted_kind: u8, wanted_len: usize) -> Option<&'a [u8]> {
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
                    if kind == wanted_kind && len == wanted_len {
                        return Some(&tail[..len - 2]);
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
    pub window_scale: Option<u8>,
}

pub fn write_header(out: &mut [u8], spec: TcpHeaderSpec) -> Result<usize, PacketError> {
    let header_len = TCP_MIN_HEADER_LEN
        + if spec.mss.is_some() { 4 } else { 0 }
        + if spec.window_scale.is_some() { 4 } else { 0 };
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
    let mut cursor = TCP_MIN_HEADER_LEN;
    if let Some(mss) = spec.mss {
        out[cursor] = 2;
        out[cursor + 1] = 4;
        out[cursor + 2..cursor + 4].copy_from_slice(&mss.to_be_bytes());
        cursor += 4;
    }
    if let Some(shift) = spec.window_scale {
        out[cursor] = 1;
        out[cursor + 1] = 3;
        out[cursor + 2] = 3;
        out[cursor + 3] = shift;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(mss: Option<u16>, window_scale: Option<u8>) -> TcpHeaderSpec {
        TcpHeaderSpec {
            source_port: 1000,
            destination_port: 2000,
            sequence: 7,
            acknowledgment: 9,
            flags: TcpFlags {
                syn: true,
                ack: true,
                ..TcpFlags::default()
            },
            window: 4096,
            mss,
            window_scale,
        }
    }

    #[test]
    fn header_roundtrip_parses_mss_and_window_scale() {
        let mut bytes = [0u8; 64];
        let length = write_header(&mut bytes, spec(Some(1460), Some(7))).expect("write");
        assert_eq!(length, 28);
        let segment = TcpSegment::parse(&bytes[..length]).expect("parse");
        assert_eq!(segment.mss(), Some(1460));
        assert_eq!(segment.window_scale(), Some(7));
        assert_eq!(segment.window(), 4096);
    }

    #[test]
    fn header_without_window_scale_omits_option() {
        let mut bytes = [0u8; 64];
        let length = write_header(&mut bytes, spec(Some(1460), None)).expect("write");
        assert_eq!(length, 24);
        let segment = TcpSegment::parse(&bytes[..length]).expect("parse");
        assert_eq!(segment.mss(), Some(1460));
        assert_eq!(segment.window_scale(), None);
    }

    #[test]
    fn window_scale_without_mss_parses() {
        let mut bytes = [0u8; 64];
        let length = write_header(&mut bytes, spec(None, Some(2))).expect("write");
        assert_eq!(length, 24);
        let segment = TcpSegment::parse(&bytes[..length]).expect("parse");
        assert_eq!(segment.mss(), None);
        assert_eq!(segment.window_scale(), Some(2));
    }

    #[test]
    fn malformed_option_length_is_rejected() {
        let mut bytes = [0u8; 24];
        write_header(&mut bytes, spec(None, None)).expect("write");
        bytes[12] = (24u8 / 4) << 4;
        bytes[20] = 3;
        bytes[21] = 1;
        let segment = TcpSegment::parse(&bytes[..24]).expect("parse");
        assert_eq!(segment.window_scale(), None);
    }
}
