// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::io;

pub const VERSION: u16 = 1;
pub const MAX_PAYLOAD: usize = 4096;
const MAGIC: [u8; 4] = *b"YAYA";
const HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Kind {
    MapsReady = 1,
    Ready = 2,
    Exec = 3,
    Shutdown = 4,
    Exit = 5,
    Error = 6,
    Status = 7,
}

impl Kind {
    fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            1 => Self::MapsReady,
            2 => Self::Ready,
            3 => Self::Exec,
            4 => Self::Shutdown,
            5 => Self::Exit,
            6 => Self::Error,
            7 => Self::Status,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    pub kind: Kind,
    pub request_id: u64,
    pub payload: &'a [u8],
}

pub fn encode(kind: Kind, request_id: u64, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control payload too large",
        ));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(kind as u16).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> io::Result<Message<'_>> {
    if bytes.len() < HEADER_LEN || bytes[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control header",
        ));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported control version",
        ));
    }
    let kind = Kind::from_raw(u16::from_le_bytes([bytes[6], bytes[7]]))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown control kind"))?;
    let length = u32::from_le_bytes(bytes[8..12].try_into().expect("control length")) as usize;
    if length > MAX_PAYLOAD || HEADER_LEN + length != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control payload length",
        ));
    }
    let request_id = u64::from_le_bytes(bytes[12..20].try_into().expect("request id"));
    Ok(Message {
        kind,
        request_id,
        payload: &bytes[HEADER_LEN..],
    })
}
