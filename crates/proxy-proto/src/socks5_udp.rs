use crate::SocksAddress;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Address<'a> {
    Socket(SocketAddr),
    Domain { name: &'a [u8], port: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram<'a> {
    pub destination: Address<'a>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("SOCKS5 UDP buffer is truncated")]
    Truncated,
    #[error("SOCKS5 UDP reserved field is nonzero")]
    InvalidReserved,
    #[error("SOCKS5 UDP fragment {0} is unsupported")]
    UnsupportedFragment(u8),
    #[error("SOCKS5 UDP address type is unsupported")]
    UnsupportedAddress,
    #[error("SOCKS5 UDP domain is empty or exceeds 255 bytes")]
    InvalidDomain,
    #[error("SOCKS5 UDP output buffer is too small")]
    OutputTooSmall,
}

pub fn encode(out: &mut [u8], destination: &SocksAddress, payload: &[u8]) -> Result<usize, Error> {
    let address_len = match destination {
        SocksAddress::Socket(SocketAddr::V4(_)) => 1 + 4 + 2,
        SocksAddress::Socket(SocketAddr::V6(_)) => 1 + 16 + 2,
        SocksAddress::Domain { name, .. } => {
            if name.is_empty() || name.len() > usize::from(u8::MAX) {
                return Err(Error::InvalidDomain);
            }
            1 + 1 + name.len() + 2
        }
    };
    let header_len = 3 + address_len;
    let total = header_len
        .checked_add(payload.len())
        .ok_or(Error::OutputTooSmall)?;
    if out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    out[..3].fill(0);
    let mut offset = 3;
    match destination {
        SocksAddress::Socket(SocketAddr::V4(address)) => {
            out[offset] = 1;
            out[offset + 1..offset + 5].copy_from_slice(&address.ip().octets());
            out[offset + 5..offset + 7].copy_from_slice(&address.port().to_be_bytes());
            offset += 7;
        }
        SocksAddress::Socket(SocketAddr::V6(address)) => {
            out[offset] = 4;
            out[offset + 1..offset + 17].copy_from_slice(&address.ip().octets());
            out[offset + 17..offset + 19].copy_from_slice(&address.port().to_be_bytes());
            offset += 19;
        }
        SocksAddress::Domain { name, port } => {
            out[offset] = 3;
            out[offset + 1] = name.len() as u8;
            let end = offset + 2 + name.len();
            out[offset + 2..end].copy_from_slice(name);
            out[end..end + 2].copy_from_slice(&port.to_be_bytes());
            offset = end + 2;
        }
    }
    debug_assert_eq!(offset, header_len);
    out[offset..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode(input: &[u8]) -> Result<Datagram<'_>, Error> {
    if input.len() < 4 {
        return Err(Error::Truncated);
    }
    if input[..2] != [0, 0] {
        return Err(Error::InvalidReserved);
    }
    if input[2] != 0 {
        return Err(Error::UnsupportedFragment(input[2]));
    }
    let (destination, payload_offset) = match input[3] {
        1 => {
            if input.len() < 10 {
                return Err(Error::Truncated);
            }
            let address = Ipv4Addr::new(input[4], input[5], input[6], input[7]);
            let port = u16::from_be_bytes([input[8], input[9]]);
            (Address::Socket(SocketAddr::from((address, port))), 10)
        }
        4 => {
            if input.len() < 22 {
                return Err(Error::Truncated);
            }
            let octets: [u8; 16] = input[4..20].try_into().map_err(|_| Error::Truncated)?;
            let port = u16::from_be_bytes([input[20], input[21]]);
            (
                Address::Socket(SocketAddr::from((Ipv6Addr::from(octets), port))),
                22,
            )
        }
        3 => {
            if input.len() < 5 {
                return Err(Error::Truncated);
            }
            let name_len = usize::from(input[4]);
            if name_len == 0 {
                return Err(Error::InvalidDomain);
            }
            let end = 5 + name_len;
            if input.len() < end + 2 {
                return Err(Error::Truncated);
            }
            let port = u16::from_be_bytes([input[end], input[end + 1]]);
            (
                Address::Domain {
                    name: &input[5..end],
                    port,
                },
                end + 2,
            )
        }
        _ => return Err(Error::UnsupportedAddress),
    };
    Ok(Datagram {
        destination,
        payload: &input[payload_offset..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_datagram_round_trips() {
        let destination = SocksAddress::Socket("198.51.100.7:53".parse().unwrap());
        let mut bytes = [0u8; 64];
        let length = encode(&mut bytes, &destination, b"query").unwrap();
        assert_eq!(&bytes[..10], &[0, 0, 0, 1, 198, 51, 100, 7, 0, 53]);
        assert_eq!(
            decode(&bytes[..length]).unwrap(),
            Datagram {
                destination: Address::Socket("198.51.100.7:53".parse().unwrap()),
                payload: b"query",
            }
        );
    }

    #[test]
    fn ipv6_and_domain_addresses_round_trip() {
        let mut bytes = [0u8; 128];
        let destination = SocksAddress::Socket("[2001:db8::7]:443".parse().unwrap());
        let length = encode(&mut bytes, &destination, b"v6").unwrap();
        assert_eq!(
            decode(&bytes[..length]).unwrap().destination,
            Address::Socket("[2001:db8::7]:443".parse().unwrap())
        );

        let destination = SocksAddress::Domain {
            name: b"example.test".to_vec(),
            port: 5353,
        };
        let length = encode(&mut bytes, &destination, b"domain").unwrap();
        assert_eq!(
            decode(&bytes[..length]).unwrap(),
            Datagram {
                destination: Address::Domain {
                    name: b"example.test",
                    port: 5353,
                },
                payload: b"domain",
            }
        );
    }

    #[test]
    fn fragments_and_invalid_headers_are_rejected() {
        assert_eq!(decode(&[0, 0, 1, 1]), Err(Error::UnsupportedFragment(1)));
        assert_eq!(decode(&[0, 1, 0, 1]), Err(Error::InvalidReserved));
        assert_eq!(decode(&[0, 0, 0, 3, 0, 0, 53]), Err(Error::InvalidDomain));
    }
}
