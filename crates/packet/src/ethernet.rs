use crate::PacketError;

pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const BROADCAST: Self = Self([0xff; 6]);

    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Other(u16),
}

impl EtherType {
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86dd,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EthernetFrame<'a> {
    bytes: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < ETHERNET_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn destination(self) -> MacAddress {
        MacAddress(
            self.bytes[0..6]
                .try_into()
                .expect("validated Ethernet header"),
        )
    }

    #[must_use]
    pub fn source(self) -> MacAddress {
        MacAddress(
            self.bytes[6..12]
                .try_into()
                .expect("validated Ethernet header"),
        )
    }

    #[must_use]
    pub fn ether_type(self) -> EtherType {
        EtherType::from_raw(u16::from_be_bytes([self.bytes[12], self.bytes[13]]))
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[ETHERNET_HEADER_LEN..]
    }
}

pub fn write_header(
    out: &mut [u8],
    destination: MacAddress,
    source: MacAddress,
    ether_type: EtherType,
) -> Result<(), PacketError> {
    if out.len() < ETHERNET_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    out[0..6].copy_from_slice(&destination.0);
    out[6..12].copy_from_slice(&source.0);
    out[12..14].copy_from_slice(&ether_type.raw().to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(
            EthernetFrame::parse(&[0; ETHERNET_HEADER_LEN - 1]).unwrap_err(),
            PacketError::Truncated
        );
    }
}
