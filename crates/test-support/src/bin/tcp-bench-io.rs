use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use serde::Serialize;

const BUFFER_SIZE: usize = 64 * 1024;

fn usage() -> &'static str {
    "usage: tcp-bench-io sink PORT BYTES | source ADDRESS PORT BYTES | \
multi-sink PORT FLOWS BYTES | multi-source ADDRESS PORT FLOWS BYTES"
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

fn multi_sink(port: u16, flow_count: usize, expected: u64) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let mut workers = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        let (mut stream, _) = listener.accept()?;
        workers.push(thread::spawn(move || -> Result<u64, String> {
            let mut buffer = [0u8; BUFFER_SIZE];
            let mut received = 0u64;
            while received < expected {
                let remaining = usize::try_from((expected - received).min(BUFFER_SIZE as u64))
                    .map_err(|error| error.to_string())?;
                let length = stream
                    .read(&mut buffer[..remaining])
                    .map_err(|error| error.to_string())?;
                if length == 0 {
                    return Err(format!("early EOF after {received} of {expected} bytes"));
                }
                received = received
                    .checked_add(length as u64)
                    .ok_or_else(|| "byte count overflow".to_owned())?;
            }
            stream.write_all(&[1]).map_err(|error| error.to_string())?;
            Ok(received)
        }));
    }
    let mut total = 0u64;
    for worker in workers {
        total = total
            .checked_add(worker.join().map_err(|_| "sink worker panicked")??)
            .ok_or("total byte count overflow")?;
    }
    println!("{total}");
    Ok(())
}

#[derive(Serialize)]
struct FlowResult {
    connect_seconds: f64,
    completion_seconds: f64,
    transfer_seconds: f64,
}

#[derive(Serialize)]
struct MultiResult {
    flow_count: usize,
    bytes_per_flow: u64,
    wall_seconds: f64,
    flows: Vec<FlowResult>,
}

fn multi_source(
    address: &str,
    port: u16,
    flow_count: usize,
    byte_count: u64,
) -> Result<(), Box<dyn Error>> {
    let barrier = Arc::new(Barrier::new(flow_count + 1));
    let mut workers = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        let barrier = Arc::clone(&barrier);
        let address = address.to_owned();
        workers.push(thread::spawn(move || -> Result<FlowResult, String> {
            barrier.wait();
            let started = Instant::now();
            let mut stream =
                TcpStream::connect((address.as_str(), port)).map_err(|error| error.to_string())?;
            stream
                .set_nodelay(true)
                .map_err(|error| error.to_string())?;
            let connected = Instant::now();
            let buffer = [0xa5; BUFFER_SIZE];
            let mut remaining = byte_count;
            while remaining > 0 {
                let length = usize::try_from(remaining.min(BUFFER_SIZE as u64))
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(&buffer[..length])
                    .map_err(|error| error.to_string())?;
                remaining -= length as u64;
            }
            let mut acknowledgment = [0u8; 1];
            stream
                .read_exact(&mut acknowledgment)
                .map_err(|error| error.to_string())?;
            if acknowledgment != [1] {
                return Err("invalid sink acknowledgment".to_owned());
            }
            let completed = Instant::now();
            Ok(FlowResult {
                connect_seconds: connected.duration_since(started).as_secs_f64(),
                completion_seconds: completed.duration_since(started).as_secs_f64(),
                transfer_seconds: completed.duration_since(connected).as_secs_f64(),
            })
        }));
    }
    let wall_started = Instant::now();
    barrier.wait();
    let mut flows = Vec::with_capacity(flow_count);
    for worker in workers {
        flows.push(worker.join().map_err(|_| "source worker panicked")??);
    }
    let result = MultiResult {
        flow_count,
        bytes_per_flow: byte_count,
        wall_seconds: wall_started.elapsed().as_secs_f64(),
        flows,
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    println!();
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, port, byte_count] if mode == "sink" => sink(port.parse()?, byte_count.parse()?),
        [mode, address, port, byte_count] if mode == "source" => {
            source(address, port.parse()?, byte_count.parse()?)
        }
        [mode, port, flows, byte_count] if mode == "multi-sink" => {
            multi_sink(port.parse()?, flows.parse()?, byte_count.parse()?)
        }
        [mode, address, port, flows, byte_count] if mode == "multi-source" => {
            multi_source(address, port.parse()?, flows.parse()?, byte_count.parse()?)
        }
        _ => Err(usage().into()),
    }
}
