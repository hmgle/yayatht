#![forbid(unsafe_code)]

pub mod checksum;
pub mod ethernet;
pub mod ip;
pub mod neighbor;
pub mod tcp;

pub use ethernet::{EtherType, EthernetFrame, MacAddress};
pub use ip::{IpPacket, Ipv4Packet, Ipv6Packet};
pub use tcp::TcpSegment;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet is truncated")]
    Truncated,
    #[error("packet contains an invalid length or offset")]
    InvalidLength,
    #[error("unsupported packet feature")]
    Unsupported,
    #[error("packet checksum is invalid")]
    InvalidChecksum,
    #[error("packet protocol does not match the expected protocol")]
    ProtocolMismatch,
}
