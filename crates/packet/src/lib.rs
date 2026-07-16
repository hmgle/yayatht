#![forbid(unsafe_code)]

pub mod checksum;
pub mod ethernet;
pub mod ip;
pub mod neighbor;
pub mod tcp;
pub mod udp;
pub mod vnet;

pub use ethernet::{EtherType, EthernetFrame, MacAddress};
pub use ip::{IpPacket, Ipv4Packet, Ipv6Packet};
pub use tcp::TcpSegment;
pub use udp::UdpDatagram;

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
