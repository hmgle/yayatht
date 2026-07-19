// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::io;
use std::os::fd::RawFd;
use yayatht_sys::control::{Kind, Message};

pub fn send(fd: RawFd, kind: Kind, request_id: u64, payload: &[u8]) -> io::Result<()> {
    let message = yayatht_sys::control::encode(kind, request_id, payload)?;
    yayatht_sys::fdpass::send_packet(fd, &message)
}

pub fn receive(fd: RawFd, buffer: &mut [u8]) -> io::Result<Message<'_>> {
    let length = yayatht_sys::fdpass::recv_packet(fd, buffer)?;
    yayatht_sys::control::decode(&buffer[..length])
}

pub fn expect(fd: RawFd, expected: Kind) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
    let message = receive(fd, &mut buffer)?;
    if message.kind == Kind::Error {
        return Err(io::Error::other(
            String::from_utf8_lossy(message.payload).into_owned(),
        ));
    }
    if message.kind != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected {expected:?}, received {:?}", message.kind),
        ));
    }
    Ok(message.payload.to_vec())
}
