use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const BUFFER_SIZE: usize = 64 * 1024;

fn usage() -> &'static str {
    "usage: tcp-bench-io sink PORT BYTES | source ADDRESS PORT BYTES"
}

fn sink(port: u16, expected: u64) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let (mut stream, _) = listener.accept()?;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut received = 0u64;
    while received < expected {
        let remaining = usize::try_from((expected - received).min(BUFFER_SIZE as u64))?;
        let length = stream.read(&mut buffer[..remaining])?;
        if length == 0 {
            return Err(format!("early EOF after {received} of {expected} bytes").into());
        }
        received = received
            .checked_add(length as u64)
            .ok_or("byte count overflow")?;
    }
    stream.write_all(&[1])?;
    println!("{received}");
    Ok(())
}

fn source(address: &str, port: u16, byte_count: u64) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect((address, port))?;
    let buffer = [0xa5; BUFFER_SIZE];
    let mut remaining = byte_count;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(BUFFER_SIZE as u64))?;
        stream.write_all(&buffer[..length])?;
        remaining -= length as u64;
    }
    let mut acknowledgment = [0u8; 1];
    stream.read_exact(&mut acknowledgment)?;
    if acknowledgment != [1] {
        return Err("invalid sink acknowledgment".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, port, byte_count] if mode == "sink" => sink(port.parse()?, byte_count.parse()?),
        [mode, address, port, byte_count] if mode == "source" => {
            source(address, port.parse()?, byte_count.parse()?)
        }
        _ => Err(usage().into()),
    }
}
