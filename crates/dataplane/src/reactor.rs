use crate::buffer::{BufferPool, FRAME_CAPACITY, FrameBuffer};
use crate::flow_table::{EpollToken, FlowId, FlowTable, Resource};
use getrandom::fill as random_fill;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};
use yayatht_packet::ethernet::{self, EtherType, EthernetFrame, MacAddress};
use yayatht_packet::ip::{self, Ipv4Packet, Ipv6Packet};
use yayatht_packet::neighbor;
use yayatht_packet::tcp::{self, TcpFlags, TcpHeaderSpec, TcpSegment};
use yayatht_proxy_proto::{Credentials, Handshake, Protocol};
use yayatht_tcp_adapter::flow::{
    ConstructionState, Flow, FlowConstruction, FlowInterface, FlowKey, FlowSide, FlowType,
    ReceiveDisposition, SendPlan, State,
};
use yayatht_tcp_adapter::sequence;

const TAP_BUDGET: usize = 32;
const TAP_TX_BUDGET: usize = 32;
const TAP_FRAME_POOL_SIZE: usize = 4096;
const EVENT_CAPACITY: usize = 128;
const RETRANSMIT_INITIAL: Duration = Duration::from_secs(1);
const MAX_RETRIES: u8 = 5;
const ZERO_WINDOW_PROBE_INITIAL: Duration = Duration::from_secs(1);
const ZERO_WINDOW_PROBE_MAX: Duration = Duration::from_secs(8);
const PROXY_RESPONSE_CAPACITY: usize = 8 * 1024;
const MAX_PENDING_SOCKET_BYTES: usize = 256 * 1024;
const TEST_DROP_TCP_DATA_ENV: &str = "YAYATHT_TEST_DROP_TCP_DATA";

#[derive(Clone, Debug)]
pub enum Upstream {
    Direct {
        host_loopback: bool,
    },
    Proxy {
        protocol: Protocol,
        address: SocketAddr,
        credentials: Option<Credentials>,
    },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub target_mac: MacAddress,
    pub gateway_mac: MacAddress,
    pub target_ipv4: Option<Ipv4Addr>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub target_ipv6: Option<Ipv6Addr>,
    pub gateway_ipv6: Option<Ipv6Addr>,
    pub upstream: Upstream,
    pub max_tcp_flows: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub tap_rx_packets: u64,
    pub tap_tx_packets: u64,
    pub parse_drops: u64,
    pub tcp_created: u64,
    pub tcp_closed: u64,
    pub tcp_retransmits: u64,
    pub tcp_zero_window_probes: u64,
    pub tcp_resets: u64,
    pub proxy_handshakes: u64,
    pub proxy_failures: u64,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("system call failed: {0}")]
    Io(#[from] io::Error),
    #[error("packet encoding failed: {0}")]
    Packet(#[from] yayatht_packet::PacketError),
    #[error("data-plane invariant failed: {0}")]
    Invariant(&'static str),
}

struct FlowEntry {
    flow: Flow,
    construction: FlowConstruction,
    socket: OwnedFd,
    transport_connected: bool,
    handshake: Option<Handshake>,
    pending_socket: PendingSocketQueue,
    pending_shutdown: bool,
    sent_segments: VecDeque<SentSegment>,
    upstream_window_clamp: Option<u16>,
    zero_window_probe: Option<ZeroWindowProbe>,
    last_namespace_byte: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
struct ZeroWindowProbe {
    deadline: Instant,
    interval: Duration,
}

impl ZeroWindowProbe {
    fn new(now: Instant) -> Self {
        Self {
            deadline: now + ZERO_WINDOW_PROBE_INITIAL,
            interval: ZERO_WINDOW_PROBE_INITIAL,
        }
    }

    fn advance(&mut self, now: Instant) {
        self.interval = (self.interval * 2).min(ZERO_WINDOW_PROBE_MAX);
        self.deadline = now + self.interval;
    }
}

#[derive(Debug)]
struct PendingSocketQueue {
    chunks: VecDeque<Vec<u8>>,
    bytes: usize,
    limit: usize,
}

impl PendingSocketQueue {
    fn new(limit: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() > self.remaining() {
            return Err(());
        }
        if !bytes.is_empty() {
            self.chunks.push_back(bytes.to_vec());
            self.bytes += bytes.len();
        }
        Ok(())
    }

    fn front(&self) -> Option<&[u8]> {
        self.chunks.front().map(Vec::as_slice)
    }

    fn consume(&mut self, length: usize) {
        let Some(front) = self.chunks.front_mut() else {
            return;
        };
        let length = length.min(front.len());
        front.drain(..length);
        self.bytes -= length;
        if front.is_empty() {
            self.chunks.pop_front();
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.bytes)
    }
}

#[derive(Clone, Debug)]
struct SentSegment {
    sequence: u32,
    payload_len: usize,
    syn: bool,
    fin: bool,
    last_sent: Instant,
    retransmit_timeout: Duration,
    retries: u8,
}

impl SentSegment {
    fn sequence_len(&self) -> u32 {
        self.payload_len as u32 + u32::from(self.syn) + u32::from(self.fin)
    }

    fn end_sequence(&self) -> u32 {
        self.sequence.wrapping_add(self.sequence_len())
    }

    fn acknowledge(&mut self, acknowledgment: u32) -> bool {
        if !sequence::after(acknowledgment, self.sequence) {
            return false;
        }
        if !sequence::before(acknowledgment, self.end_sequence()) {
            return true;
        }
        let mut acknowledged = sequence::distance(self.sequence, acknowledgment);
        self.sequence = acknowledgment;
        if self.syn && acknowledged > 0 {
            self.syn = false;
            acknowledged -= 1;
        }
        let payload = usize::try_from(acknowledged)
            .unwrap_or(usize::MAX)
            .min(self.payload_len);
        self.payload_len -= payload;
        acknowledged -= payload as u32;
        if self.fin && acknowledged > 0 {
            self.fin = false;
        }
        false
    }

    fn flags(&self) -> TcpFlags {
        TcpFlags {
            syn: self.syn,
            fin: self.fin,
            psh: self.payload_len > 0,
            ack: true,
            ..TcpFlags::default()
        }
    }
}

struct QueuedFrame {
    flow: Option<FlowId>,
    frame: PooledFrame,
    plan: Option<SendPlan>,
}

struct PooledFrame {
    pool_index: usize,
    buffer: FrameBuffer,
}

enum PeekedFrame {
    Data { frame: PooledFrame, length: usize },
    Eof,
    WouldBlock,
}

#[derive(Clone, Copy)]
struct TcpFrameSpec {
    key: FlowKey,
    plan: SendPlan,
    flags: TcpFlags,
    mss: Option<u16>,
    window: u16,
    payload_len: usize,
}

pub struct Reactor {
    config: Config,
    tap: OwnedFd,
    control: OwnedFd,
    epoll: yayatht_sys::reactor::Epoll,
    timer: yayatht_sys::reactor::TimerFd,
    flows: FlowTable<FlowEntry>,
    by_key: HashMap<FlowKey, FlowId>,
    frame_pool: BufferPool,
    tap_queue: VecDeque<QueuedFrame>,
    metrics: Metrics,
    shutting_down: bool,
    test_drop_tcp_data: usize,
}

impl Reactor {
    pub fn new(config: Config, tap: OwnedFd, control: OwnedFd) -> Result<Self, Error> {
        let epoll = yayatht_sys::reactor::Epoll::new()?;
        let timer = yayatht_sys::reactor::TimerFd::periodic(Duration::from_millis(100))?;
        epoll.add(
            tap.as_raw_fd(),
            yayatht_sys::reactor::READABLE,
            EpollToken::global(Resource::Tap).raw(),
        )?;
        epoll.add(
            timer.as_raw_fd(),
            yayatht_sys::reactor::READABLE,
            EpollToken::global(Resource::Timer).raw(),
        )?;
        epoll.add(
            control.as_raw_fd(),
            yayatht_sys::reactor::READABLE,
            EpollToken::global(Resource::Control).raw(),
        )?;
        let max_tcp_flows = config.max_tcp_flows;
        Ok(Self {
            config,
            tap,
            control,
            epoll,
            timer,
            flows: FlowTable::with_capacity(max_tcp_flows),
            by_key: HashMap::with_capacity(max_tcp_flows),
            frame_pool: BufferPool::new(TAP_FRAME_POOL_SIZE),
            tap_queue: VecDeque::new(),
            metrics: Metrics::default(),
            shutting_down: false,
            test_drop_tcp_data: test_drop_tcp_data_count(),
        })
    }

    pub fn run(mut self) -> Result<Metrics, Error> {
        let mut events = [yayatht_sys::reactor::Event::default(); EVENT_CAPACITY];
        while !self.shutting_down || !self.flows.active_ids().is_empty() {
            let count = self.epoll.wait(&mut events, Some(Duration::from_secs(1)))?;
            for event in &events[..count] {
                let Some((flow, resource, _side)) = EpollToken::from_raw(event.token).decode()
                else {
                    warn!(token = event.token, "dropping invalid epoll token");
                    continue;
                };
                match (flow, resource) {
                    (None, Resource::Tap) => {
                        if event.events & yayatht_sys::reactor::READABLE != 0 {
                            self.handle_tap()?;
                        }
                        if event.events & yayatht_sys::reactor::WRITABLE != 0 {
                            self.flush_tap_queue()?;
                        }
                    }
                    (None, Resource::Timer) => {
                        self.timer.consume()?;
                        self.handle_timers()?;
                    }
                    (None, Resource::Control) => self.handle_control()?,
                    (Some(id), Resource::UpstreamSocket) => self.handle_socket(id, event.events)?,
                    _ => {}
                }
            }
            self.cleanup_closed();
            if self.shutting_down {
                for id in self.flows.active_ids() {
                    self.close_flow(id)?;
                }
            }
        }
        Ok(self.metrics)
    }

    fn handle_control(&mut self) -> Result<(), Error> {
        let mut message = [0u8; 64];
        match yayatht_sys::fdpass::recv_packet(self.control.as_raw_fd(), &mut message) {
            Ok(length) => {
                let message = yayatht_sys::control::decode(&message[..length])?;
                if message.kind == yayatht_sys::control::Kind::Shutdown {
                    self.shutting_down = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => self.shutting_down = true,
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn handle_tap(&mut self) -> Result<(), Error> {
        for _ in 0..TAP_BUDGET {
            if self.frame_pool.available() == 0 {
                self.update_tap_interest()?;
                break;
            }
            let mut bytes = [0u8; 2048];
            let length = match yayatht_sys::reactor::read(self.tap.as_raw_fd(), &mut bytes) {
                Ok(0) => return Err(Error::Invariant("TAP returned EOF")),
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            self.metrics.tap_rx_packets += 1;
            if let Err(error) = self.handle_frame(&bytes[..length]) {
                debug!(%error, "dropping TAP frame");
                self.metrics.parse_drops += 1;
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let ethernet = EthernetFrame::parse(bytes)?;
        match ethernet.ether_type() {
            EtherType::Arp => self.handle_arp(ethernet),
            EtherType::Ipv4 => self.handle_ipv4(ethernet),
            EtherType::Ipv6 => self.handle_ipv6(ethernet),
            _ => Ok(()),
        }
    }

    fn handle_arp(&mut self, ethernet: EthernetFrame<'_>) -> Result<(), Error> {
        let Some(gateway) = self.config.gateway_ipv4 else {
            return Ok(());
        };
        let request = neighbor::parse_arp_request(ethernet.payload())?;
        if request.target_ip != gateway.octets() {
            return Ok(());
        }
        let mut frame = self.acquire_frame()?;
        let length = match neighbor::write_arp_reply(
            frame.buffer.writable(),
            self.config.gateway_mac,
            gateway.octets(),
            request,
        ) {
            Ok(length) => length,
            Err(error) => {
                self.release_frame(frame);
                return Err(error.into());
            }
        };
        frame.buffer.set_len(length);
        self.queue_tap(None, frame, None)
    }

    fn handle_ipv4(&mut self, ethernet: EthernetFrame<'_>) -> Result<(), Error> {
        let packet = Ipv4Packet::parse(ethernet.payload())?;
        if packet.protocol() != ip::IPPROTO_TCP {
            return Ok(());
        }
        let segment = TcpSegment::parse_ipv4(packet)?;
        let key = FlowKey {
            namespace: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(packet.source())),
                segment.source_port(),
            ),
            target: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(packet.destination())),
                segment.destination_port(),
            ),
        };
        self.handle_tcp(key, segment)
    }

    fn handle_ipv6(&mut self, ethernet: EthernetFrame<'_>) -> Result<(), Error> {
        let packet = Ipv6Packet::parse(ethernet.payload())?;
        if packet.next_header() == ip::IPPROTO_ICMPV6 {
            if packet.payload().first().copied() != Some(135) {
                return Ok(());
            }
            let Some(gateway) = self.config.gateway_ipv6 else {
                return Ok(());
            };
            let target = neighbor::parse_neighbor_solicitation(packet)?;
            debug!(target = %Ipv6Addr::from(target), source = %Ipv6Addr::from(packet.source()), "received neighbor solicitation");
            if target != gateway.octets() {
                return Ok(());
            }
            let mut frame = self.acquire_frame()?;
            let length = match neighbor::write_neighbor_advertisement(
                frame.buffer.writable(),
                self.config.gateway_mac,
                ethernet.source(),
                gateway.octets(),
                packet.source(),
            ) {
                Ok(length) => length,
                Err(error) => {
                    self.release_frame(frame);
                    return Err(error.into());
                }
            };
            frame.buffer.set_len(length);
            debug!(gateway = %gateway, "sending neighbor advertisement");
            return self.queue_tap(None, frame, None);
        }
        if packet.next_header() != ip::IPPROTO_TCP {
            return Ok(());
        }
        let segment = TcpSegment::parse_ipv6(packet)?;
        debug!(source = %Ipv6Addr::from(packet.source()), destination = %Ipv6Addr::from(packet.destination()), flags = ?segment.flags(), "received IPv6 TCP segment");
        let key = FlowKey {
            namespace: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(packet.source())),
                segment.source_port(),
            ),
            target: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(packet.destination())),
                segment.destination_port(),
            ),
        };
        self.handle_tcp(key, segment)
    }

    fn handle_tcp(&mut self, key: FlowKey, segment: TcpSegment<'_>) -> Result<(), Error> {
        if let Some(&id) = self.by_key.get(&key) {
            return self.handle_existing_tcp(id, segment);
        }
        let flags = segment.flags();
        if !flags.syn || flags.ack || flags.rst {
            return Ok(());
        }
        let target_side = self.target_side(key.target);
        let (socket, connected) =
            match yayatht_sys::socket::connect_nonblocking(target_side.transport_endpoint) {
                Ok(result) => result,
                Err(_) => {
                    let frame = self.build_reset(key, segment.sequence().wrapping_add(1))?;
                    self.metrics.tcp_resets += 1;
                    return self.queue_tap(None, frame, None);
                }
            };
        let mut random = [0u8; 4];
        random_fill(&mut random)
            .map_err(|error| io::Error::other(format!("getrandom failed: {error:?}")))?;
        let default_mss = if key.target.is_ipv4() { 1460 } else { 1440 };
        let negotiated_mss = segment
            .mss()
            .filter(|mss| *mss >= 536)
            .unwrap_or(default_mss)
            .min(default_mss);
        let mut construction = FlowConstruction::new();
        construction
            .set_initiating(FlowSide {
                endpoint: key.namespace,
                transport_endpoint: key.namespace,
                interface: FlowInterface::NamespaceTap,
            })
            .map_err(|_| Error::Invariant("unable to set initiating flow side"))?;
        construction
            .set_target(target_side)
            .map_err(|_| Error::Invariant("unable to set target flow side"))?;
        construction
            .set_type(FlowType::Tcp)
            .map_err(|_| Error::Invariant("unable to type TCP flow"))?;
        let entry = FlowEntry {
            flow: Flow::new(
                key,
                segment.sequence(),
                u32::from_ne_bytes(random),
                negotiated_mss,
            ),
            construction,
            socket,
            transport_connected: false,
            handshake: self.proxy_handshake(key.target),
            pending_socket: PendingSocketQueue::new(MAX_PENDING_SOCKET_BYTES),
            pending_shutdown: false,
            sent_segments: VecDeque::new(),
            upstream_window_clamp: None,
            zero_window_probe: None,
            last_namespace_byte: None,
        };
        let id = match self.flows.insert(entry) {
            Ok(id) => id,
            Err(_) => {
                let frame = self.build_reset(key, segment.sequence().wrapping_add(1))?;
                self.metrics.tcp_resets += 1;
                return self.queue_tap(None, frame, None);
            }
        };
        self.by_key.insert(key, id);
        let token = EpollToken::flow(id, Resource::UpstreamSocket, true)
            .ok_or(Error::Invariant("unable to encode flow token"))?;
        let fd = self
            .flows
            .get(id)
            .expect("inserted flow")
            .socket
            .as_raw_fd();
        self.epoll.add(
            fd,
            yayatht_sys::reactor::READABLE
                | yayatht_sys::reactor::WRITABLE
                | yayatht_sys::reactor::ERROR
                | yayatht_sys::reactor::READ_HANGUP,
            token.raw(),
        )?;
        self.flows
            .get_mut(id)
            .expect("inserted flow")
            .construction
            .activate()
            .map_err(|_| Error::Invariant("unable to activate TCP flow"))?;
        self.metrics.tcp_created += 1;
        if connected {
            self.finish_transport_connect(id)?;
        }
        Ok(())
    }

    fn handle_existing_tcp(&mut self, id: FlowId, segment: TcpSegment<'_>) -> Result<(), Error> {
        let flags = segment.flags();
        let state = self.flows.get(id).expect("flow exists").flow.state();
        if flags.syn && !flags.ack {
            if state == State::Connecting {
                return Ok(());
            }
            if state == State::SynReceived {
                return self.retransmit_oldest(id, false);
            }
        }
        let previous_ack = self
            .flows
            .get(id)
            .ok_or(Error::Invariant("flow disappeared"))?
            .flow
            .local_unacked();
        let disposition = {
            let entry = self
                .flows
                .get_mut(id)
                .ok_or(Error::Invariant("flow disappeared"))?;
            entry.flow.receive(
                segment.sequence(),
                flags.ack.then_some(segment.acknowledgment()),
                segment.window(),
                segment.payload().len(),
                flags.fin,
                flags.rst,
            )
        };
        if disposition == ReceiveDisposition::Reset {
            return self.close_flow(id);
        }
        self.refresh_window_clamp(id)?;
        self.refresh_zero_window_probe(id, Instant::now());
        let current_ack = self
            .flows
            .get(id)
            .expect("flow exists")
            .flow
            .local_unacked();
        if current_ack != previous_ack {
            let acked = self
                .flows
                .get(id)
                .expect("flow exists")
                .flow
                .newly_acked_payload(previous_ack);
            if acked > 0 {
                let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
                let discarded = yayatht_sys::socket::discard(fd, acked)?;
                if discarded != acked {
                    return Err(Error::Invariant("socket ACK consume length mismatch"));
                }
            }
            let segments = &mut self.flows.get_mut(id).expect("flow exists").sent_segments;
            while segments
                .front_mut()
                .is_some_and(|segment| segment.acknowledge(current_ack))
            {
                segments.pop_front();
            }
        }
        match disposition {
            ReceiveDisposition::InOrder { payload_len, fin } => {
                if payload_len > 0 {
                    self.submit_namespace_payload(id, segment.payload())?;
                }
                if fin {
                    let entry = self.flows.get_mut(id).expect("flow exists");
                    if entry.pending_socket.is_empty() {
                        yayatht_sys::socket::shutdown_write(entry.socket.as_raw_fd())?;
                    } else {
                        entry.pending_shutdown = true;
                    }
                    self.send_ack(id)?;
                }
            }
            ReceiveDisposition::Duplicate
            | ReceiveDisposition::OutOfOrder
            | ReceiveDisposition::OutsideWindow => self.send_ack(id)?,
            ReceiveDisposition::Invalid => self.close_flow(id)?,
            ReceiveDisposition::Reset => {}
        }
        self.refresh_upstream_ack(id)?;
        if self
            .flows
            .get(id)
            .is_some_and(|entry| entry.flow.state() == State::TimeWait)
        {
            self.close_flow(id)?;
        }
        Ok(())
    }

    fn submit_namespace_payload(&mut self, id: FlowId, payload: &[u8]) -> Result<(), Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        match yayatht_sys::socket::send(fd, payload) {
            Ok(sent) => {
                self.flows
                    .get_mut(id)
                    .expect("flow exists")
                    .flow
                    .record_upstream_submitted(sent);
                if sent < payload.len() {
                    self.flows
                        .get_mut(id)
                        .expect("flow exists")
                        .pending_socket
                        .push(&payload[sent..])
                        .map_err(|()| Error::Invariant("pending socket queue exceeded limit"))?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.flows
                    .get_mut(id)
                    .expect("flow exists")
                    .pending_socket
                    .push(payload)
                    .map_err(|()| Error::Invariant("pending socket queue exceeded limit"))?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn handle_socket(&mut self, id: FlowId, events: u32) -> Result<(), Error> {
        if self.flow_is_closed(id) {
            return Ok(());
        }
        if events & yayatht_sys::reactor::ERROR != 0 {
            let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
            if yayatht_sys::socket::pending_error(fd)?.is_some() {
                self.send_reset_for_flow(id)?;
                return self.close_flow(id);
            }
        }
        if !self.flows.get(id).expect("flow exists").transport_connected
            && events & yayatht_sys::reactor::WRITABLE != 0
        {
            self.finish_transport_connect(id)?;
        }
        if self.flow_is_closed(id) {
            return Ok(());
        }
        if self
            .flows
            .get(id)
            .is_some_and(|entry| entry.handshake.is_some())
        {
            if events & yayatht_sys::reactor::WRITABLE != 0 {
                self.flush_proxy_output(id)?;
            }
            if self.flow_is_closed(id) {
                return Ok(());
            }
            if events & (yayatht_sys::reactor::READABLE | yayatht_sys::reactor::READ_HANGUP) != 0 {
                self.receive_proxy_input(id)?;
            }
            if self.flow_is_closed(id)
                || self
                    .flows
                    .get(id)
                    .is_none_or(|entry| entry.handshake.is_some())
            {
                return Ok(());
            }
        }
        if events & yayatht_sys::reactor::WRITABLE != 0 {
            self.flush_socket_queue(id)?;
        }
        self.refresh_upstream_ack(id)?;
        if events & (yayatht_sys::reactor::READABLE | yayatht_sys::reactor::READ_HANGUP) != 0 {
            self.send_socket_data(id)?;
        }
        Ok(())
    }

    fn finish_transport_connect(&mut self, id: FlowId) -> Result<(), Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        if yayatht_sys::socket::pending_error(fd)?.is_some() {
            self.send_reset_for_flow(id)?;
            return self.close_flow(id);
        }
        self.flows
            .get_mut(id)
            .expect("flow exists")
            .transport_connected = true;
        if self
            .flows
            .get(id)
            .is_some_and(|entry| entry.handshake.is_some())
        {
            self.flush_proxy_output(id)
        } else {
            self.activate_flow(id)
        }
    }

    fn activate_flow(&mut self, id: FlowId) -> Result<(), Error> {
        self.refresh_namespace_window(id)?;
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let info = yayatht_sys::tcp_info::get(fd)?;
        let plan = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .socket_connected(info.bytes_acked);
        let frame = self.build_flow_frame(
            id,
            plan,
            &[],
            TcpFlags {
                syn: true,
                ack: true,
                ..TcpFlags::default()
            },
        )?;
        self.queue_tap(Some(id), frame, Some(plan))
    }

    fn flush_proxy_output(&mut self, id: FlowId) -> Result<(), Error> {
        loop {
            let send_result = {
                let entry = self.flows.get(id).expect("flow exists");
                let handshake = entry.handshake.as_ref().expect("proxy handshake exists");
                if handshake.output().is_empty() {
                    break;
                }
                yayatht_sys::socket::send(entry.socket.as_raw_fd(), handshake.output())
            };
            match send_result {
                Ok(0) => {
                    self.fail_proxy_handshake(id, "proxy handshake send returned zero")?;
                    break;
                }
                Ok(sent) => self
                    .flows
                    .get_mut(id)
                    .expect("flow exists")
                    .handshake
                    .as_mut()
                    .expect("proxy handshake exists")
                    .advance_output(sent)
                    .map_err(|error| io::Error::other(error.to_string()))?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.fail_proxy_handshake(id, &error.to_string())?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn receive_proxy_input(&mut self, id: FlowId) -> Result<(), Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let mut response = [0u8; PROXY_RESPONSE_CAPACITY];
        let length = match yayatht_sys::socket::peek(fd, &mut response) {
            Ok(0) => {
                self.fail_proxy_handshake(id, "proxy closed during handshake")?;
                return Ok(());
            }
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => {
                self.fail_proxy_handshake(id, &error.to_string())?;
                return Ok(());
            }
        };
        let consumed = match self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .handshake
            .as_mut()
            .expect("proxy handshake exists")
            .receive(&response[..length])
        {
            Ok(consumed) => consumed,
            Err(error) => {
                self.fail_proxy_handshake(id, &error.to_string())?;
                return Ok(());
            }
        };
        if consumed > 0 {
            let discarded = match yayatht_sys::socket::discard(fd, consumed) {
                Ok(discarded) => discarded,
                Err(error) => {
                    self.fail_proxy_handshake(id, &error.to_string())?;
                    return Ok(());
                }
            };
            if discarded != consumed {
                self.fail_proxy_handshake(id, "proxy response consume length mismatch")?;
                return Ok(());
            }
        }
        if self.flows.get(id).is_none() {
            return Ok(());
        }
        if self
            .flows
            .get(id)
            .expect("flow exists")
            .handshake
            .as_ref()
            .expect("proxy handshake exists")
            .is_complete()
        {
            self.flows.get_mut(id).expect("flow exists").handshake = None;
            self.metrics.proxy_handshakes += 1;
            self.activate_flow(id)?;
        } else {
            self.flush_proxy_output(id)?;
        }
        Ok(())
    }

    fn fail_proxy_handshake(&mut self, id: FlowId, reason: &str) -> Result<(), Error> {
        warn!(%reason, "proxy handshake failed");
        self.metrics.proxy_failures += 1;
        self.send_reset_for_flow(id)?;
        self.close_flow(id)
    }

    fn flow_is_closed(&self, id: FlowId) -> bool {
        self.flows
            .get(id)
            .is_none_or(|entry| entry.flow.state() == State::Closed)
    }

    fn flush_socket_queue(&mut self, id: FlowId) -> Result<(), Error> {
        loop {
            let send_result = {
                let entry = self.flows.get(id).expect("flow exists");
                let Some(bytes) = entry.pending_socket.front() else {
                    break;
                };
                yayatht_sys::socket::send(entry.socket.as_raw_fd(), bytes)
            };
            match send_result {
                Ok(0) => {
                    return Err(Error::Invariant("socket queue send returned zero"));
                }
                Ok(sent) => {
                    let entry = self.flows.get_mut(id).expect("flow exists");
                    entry.pending_socket.consume(sent);
                    entry.flow.record_upstream_submitted(sent);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
            if !self
                .flows
                .get(id)
                .expect("flow exists")
                .pending_socket
                .is_empty()
            {
                break;
            }
        }
        let entry = self.flows.get_mut(id).expect("flow exists");
        if entry.pending_socket.is_empty() && entry.pending_shutdown {
            yayatht_sys::socket::shutdown_write(entry.socket.as_raw_fd())?;
            entry.pending_shutdown = false;
        }
        Ok(())
    }

    fn refresh_upstream_ack(&mut self, id: FlowId) -> Result<(), Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let info = yayatht_sys::tcp_info::get(fd)?;
        let advanced = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .record_upstream_ack(info.bytes_acked);
        let window_changed = self.update_namespace_window(id, info.send_window)?;
        if advanced || window_changed {
            self.send_ack(id)?;
        }
        Ok(())
    }

    fn refresh_namespace_window(&mut self, id: FlowId) -> Result<(), Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let info = yayatht_sys::tcp_info::get(fd)?;
        self.update_namespace_window(id, info.send_window)?;
        Ok(())
    }

    fn update_namespace_window(&mut self, id: FlowId, send_window: u32) -> Result<bool, Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let socket_available = yayatht_sys::socket::send_buffer_available(fd)?;
        let queue_available = self
            .flows
            .get(id)
            .expect("flow exists")
            .pending_socket
            .remaining();
        let available = socket_available
            .min(queue_available)
            .min(send_window as usize)
            .min(usize::from(u16::MAX));
        let window = u16::try_from(available).expect("window clamped to u16");
        Ok(self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .set_advertised_window(window))
    }

    fn refresh_window_clamp(&mut self, id: FlowId) -> Result<(), Error> {
        let (fd, window, previous) = {
            let entry = self.flows.get(id).expect("flow exists");
            (
                entry.socket.as_raw_fd(),
                entry.flow.peer_window(),
                entry.upstream_window_clamp,
            )
        };
        if previous == Some(window) {
            return Ok(());
        }
        yayatht_sys::tcp_info::set_window_clamp(fd, u32::from(window).max(1))?;
        self.flows
            .get_mut(id)
            .expect("flow exists")
            .upstream_window_clamp = Some(window);
        Ok(())
    }

    fn refresh_zero_window_probe(&mut self, id: FlowId, now: Instant) {
        let entry = self.flows.get_mut(id).expect("flow exists");
        let should_probe = entry.flow.peer_window() == 0
            && matches!(
                entry.flow.state(),
                State::Established | State::NamespaceFinReceived
            );
        if should_probe {
            entry
                .zero_window_probe
                .get_or_insert_with(|| ZeroWindowProbe::new(now));
        } else {
            entry.zero_window_probe = None;
        }
    }

    fn send_socket_data(&mut self, id: FlowId) -> Result<(), Error> {
        for _ in 0..TAP_TX_BUDGET {
            if self.frame_pool.available() == 0 {
                break;
            }
            if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
                break;
            }
            let (state, payload_offset, window, mss) = {
                let entry = self.flows.get(id).expect("flow exists");
                (
                    entry.flow.state(),
                    entry
                        .sent_segments
                        .iter()
                        .map(|segment| segment.payload_len)
                        .sum::<usize>(),
                    entry.flow.available_namespace_window(),
                    usize::from(entry.flow.mss()),
                )
            };
            if !matches!(state, State::Established | State::NamespaceFinReceived) || window == 0 {
                break;
            }
            match self.peek_socket_frame(id, payload_offset, mss.min(window))? {
                PeekedFrame::Eof => {
                    let plan = self
                        .flows
                        .get(id)
                        .expect("flow exists")
                        .flow
                        .plan_send(0, true)
                        .ok_or(Error::Invariant("unable to plan FIN"))?;
                    let frame = self.build_flow_frame(
                        id,
                        plan,
                        &[],
                        TcpFlags {
                            fin: true,
                            ack: true,
                            ..TcpFlags::default()
                        },
                    )?;
                    self.queue_tap(Some(id), frame, Some(plan))?;
                }
                PeekedFrame::Data { mut frame, length } => {
                    let plan = self
                        .flows
                        .get(id)
                        .expect("flow exists")
                        .flow
                        .plan_send(length, false)
                        .ok_or(Error::Invariant("unable to plan TCP payload"))?;
                    let key = self.flows.get(id).expect("flow exists").flow.key();
                    let last_byte =
                        frame.buffer.writable()[Self::tcp_payload_offset(key, None) + length - 1];
                    self.flows
                        .get_mut(id)
                        .expect("flow exists")
                        .last_namespace_byte = Some(last_byte);
                    let frame = self.finalize_flow_payload_frame(
                        id,
                        frame,
                        plan,
                        TcpFlags {
                            psh: true,
                            ack: true,
                            ..TcpFlags::default()
                        },
                        length,
                    )?;
                    self.queue_tap(Some(id), frame, Some(plan))?;
                }
                PeekedFrame::WouldBlock => break,
            }
        }
        Ok(())
    }

    fn send_ack(&mut self, id: FlowId) -> Result<(), Error> {
        let plan = {
            let flow = &self.flows.get(id).expect("flow exists").flow;
            SendPlan {
                sequence: flow.local_next(),
                acknowledgment: flow.namespace_ack(),
                length: 0,
                syn: false,
                fin: false,
            }
        };
        let frame = self.build_flow_frame(
            id,
            plan,
            &[],
            TcpFlags {
                ack: true,
                ..TcpFlags::default()
            },
        )?;
        self.queue_tap(None, frame, None)
    }

    fn handle_timers(&mut self) -> Result<(), Error> {
        let now = Instant::now();
        for id in self.flows.active_ids() {
            if self.frame_pool.available() == 0 {
                break;
            }
            let retransmit = {
                let entry = self.flows.get(id).expect("flow exists");
                entry.zero_window_probe.is_none()
                    && entry.sent_segments.front().is_some_and(|segment| {
                        now.duration_since(segment.last_sent) >= segment.retransmit_timeout
                    })
            };
            if retransmit {
                if self
                    .flows
                    .get(id)
                    .expect("flow exists")
                    .sent_segments
                    .front()
                    .is_some_and(|segment| segment.retries >= MAX_RETRIES)
                {
                    self.send_reset_for_flow(id)?;
                    self.close_flow(id)?;
                    continue;
                }
                self.retransmit_oldest(id, true)?;
            }
            let probe_due = self
                .flows
                .get(id)
                .and_then(|entry| entry.zero_window_probe)
                .is_some_and(|probe| probe.deadline <= now);
            if probe_due {
                self.send_zero_window_probe(id, now)?;
            }
        }
        Ok(())
    }

    fn send_zero_window_probe(&mut self, id: FlowId, now: Instant) -> Result<(), Error> {
        if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
            return Ok(());
        }
        let (fd, sequence, acknowledgment, fallback_byte, retained_payload) = {
            let entry = self.flows.get(id).expect("flow exists");
            let retained = entry
                .sent_segments
                .front()
                .filter(|segment| segment.payload_len > 0);
            (
                entry.socket.as_raw_fd(),
                retained.map_or_else(|| entry.flow.local_next().wrapping_sub(1), |s| s.sequence),
                entry.flow.namespace_ack(),
                entry.last_namespace_byte,
                retained.is_some(),
            )
        };
        yayatht_sys::tcp_info::set_peek_offset(fd, 0)?;
        let mut socket_byte = [0u8; 1];
        let length = match yayatht_sys::socket::peek(fd, &mut socket_byte) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
            Err(error) => return Err(error.into()),
        };
        if length == 0 {
            if let Some(probe) = self
                .flows
                .get_mut(id)
                .expect("flow exists")
                .zero_window_probe
                .as_mut()
            {
                probe.advance(now);
            }
            return Ok(());
        }
        let payload = if retained_payload {
            socket_byte
        } else {
            [fallback_byte.unwrap_or(socket_byte[0])]
        };
        let plan = SendPlan {
            sequence,
            acknowledgment,
            length: 1,
            syn: false,
            fin: false,
        };
        let frame = self.build_flow_frame(
            id,
            plan,
            &payload,
            TcpFlags {
                psh: true,
                ack: true,
                ..TcpFlags::default()
            },
        )?;
        self.queue_tap(Some(id), frame, None)?;
        if let Some(probe) = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .zero_window_probe
            .as_mut()
        {
            probe.advance(now);
        }
        self.metrics.tcp_zero_window_probes += 1;
        debug!(flow_slot = id.slot, "sent TCP zero-window probe");
        Ok(())
    }

    fn retransmit_oldest(&mut self, id: FlowId, backoff: bool) -> Result<(), Error> {
        if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
            return Ok(());
        }
        let (segment, acknowledgment) = {
            let entry = self.flows.get(id).expect("flow exists");
            let Some(segment) = entry.sent_segments.front() else {
                return Ok(());
            };
            (segment.clone(), entry.flow.namespace_ack())
        };
        let plan = SendPlan {
            sequence: segment.sequence,
            acknowledgment,
            length: segment.payload_len,
            syn: segment.syn,
            fin: segment.fin,
        };
        let frame = if segment.payload_len > 0 {
            match self.peek_socket_frame(id, 0, segment.payload_len)? {
                PeekedFrame::Data { frame, length } if length == segment.payload_len => {
                    self.finalize_flow_payload_frame(id, frame, plan, segment.flags(), length)?
                }
                PeekedFrame::Data { frame, .. } => {
                    self.release_frame(frame);
                    self.fail_tcp_flow(id, "retained socket payload is shorter than segment")?;
                    return Ok(());
                }
                PeekedFrame::WouldBlock => {
                    self.fail_tcp_flow(id, "retained socket payload is unavailable")?;
                    return Ok(());
                }
                PeekedFrame::Eof => {
                    self.fail_tcp_flow(id, "retained socket payload reached EOF")?;
                    return Ok(());
                }
            }
        } else {
            self.build_flow_frame(id, plan, &[], segment.flags())?
        };
        self.queue_tap(Some(id), frame, None)?;
        let segment = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .sent_segments
            .front_mut()
            .ok_or(Error::Invariant("retransmitted segment disappeared"))?;
        segment.last_sent = Instant::now();
        if backoff {
            segment.retries += 1;
            segment.retransmit_timeout =
                (segment.retransmit_timeout * 2).min(Duration::from_secs(8));
        }
        self.metrics.tcp_retransmits += 1;
        Ok(())
    }

    fn fail_tcp_flow(&mut self, id: FlowId, reason: &str) -> Result<(), Error> {
        warn!(%reason, "TCP flow invariant failed");
        self.send_reset_for_flow(id)?;
        self.close_flow(id)
    }

    fn target_side(&self, logical: SocketAddr) -> FlowSide {
        match &self.config.upstream {
            Upstream::Proxy { address, .. } => FlowSide {
                endpoint: logical,
                transport_endpoint: *address,
                interface: FlowInterface::ProxyTunnel,
            },
            Upstream::Direct {
                host_loopback: false,
            } => FlowSide {
                endpoint: logical,
                transport_endpoint: logical,
                interface: FlowInterface::HostSocket,
            },
            Upstream::Direct {
                host_loopback: true,
            } => FlowSide {
                endpoint: logical,
                transport_endpoint: match logical {
                    SocketAddr::V4(address) if Some(*address.ip()) == self.config.gateway_ipv4 => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
                    }
                    SocketAddr::V6(address) if Some(*address.ip()) == self.config.gateway_ipv6 => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), address.port())
                    }
                    _ => logical,
                },
                interface: FlowInterface::HostSocket,
            },
        }
    }

    fn proxy_handshake(&self, logical: SocketAddr) -> Option<Handshake> {
        match &self.config.upstream {
            Upstream::Direct { .. } => None,
            Upstream::Proxy {
                protocol,
                credentials,
                ..
            } => Some(Handshake::new(*protocol, logical, credentials.clone())),
        }
    }

    fn peek_socket_frame(
        &mut self,
        id: FlowId,
        offset: usize,
        capacity: usize,
    ) -> Result<PeekedFrame, Error> {
        let (key, fd) = {
            let entry = self.flows.get(id).expect("flow exists");
            (entry.flow.key(), entry.socket.as_raw_fd())
        };
        let payload_offset = Self::tcp_payload_offset(key, None);
        let capacity = capacity.min(FRAME_CAPACITY - payload_offset);
        let offset = i32::try_from(offset)
            .map_err(|_| Error::Invariant("socket peek offset exceeds i32"))?;
        yayatht_sys::tcp_info::set_peek_offset(fd, offset)?;
        let mut frame = self.acquire_frame()?;
        let result = yayatht_sys::socket::peek(
            fd,
            &mut frame.buffer.writable()[payload_offset..payload_offset + capacity],
        );
        match result {
            Ok(0) => {
                self.release_frame(frame);
                Ok(PeekedFrame::Eof)
            }
            Ok(length) => Ok(PeekedFrame::Data { frame, length }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.release_frame(frame);
                Ok(PeekedFrame::WouldBlock)
            }
            Err(error) => {
                self.release_frame(frame);
                Err(error.into())
            }
        }
    }

    fn flow_frame_parameters(&self, id: FlowId) -> Result<(FlowKey, u16, u16), Error> {
        let entry = self
            .flows
            .get(id)
            .ok_or(Error::Invariant("flow disappeared"))?;
        if entry.construction.state() != ConstructionState::Active
            || entry.construction.active_sides().is_none()
        {
            return Err(Error::Invariant("inactive flow reached packet builder"));
        }
        Ok((
            entry.flow.key(),
            entry.flow.mss(),
            entry.flow.advertised_window(),
        ))
    }

    fn finalize_flow_payload_frame(
        &mut self,
        id: FlowId,
        mut frame: PooledFrame,
        plan: SendPlan,
        flags: TcpFlags,
        payload_len: usize,
    ) -> Result<PooledFrame, Error> {
        let (key, _, window) = match self.flow_frame_parameters(id) {
            Ok(parameters) => parameters,
            Err(error) => {
                self.release_frame(frame);
                return Err(error);
            }
        };
        let spec = TcpFrameSpec {
            key,
            plan,
            flags,
            mss: None,
            window,
            payload_len,
        };
        if let Err(error) = self.finalize_tcp_frame(&mut frame, spec) {
            self.release_frame(frame);
            return Err(error);
        }
        Ok(frame)
    }

    fn build_flow_frame(
        &mut self,
        id: FlowId,
        plan: SendPlan,
        payload: &[u8],
        flags: TcpFlags,
    ) -> Result<PooledFrame, Error> {
        let (key, mss, window) = self.flow_frame_parameters(id)?;
        self.build_tcp_frame(key, plan, payload, flags, flags.syn.then_some(mss), window)
    }

    fn build_reset(&mut self, key: FlowKey, acknowledgment: u32) -> Result<PooledFrame, Error> {
        self.build_tcp_frame(
            key,
            SendPlan {
                sequence: 0,
                acknowledgment,
                length: 0,
                syn: false,
                fin: false,
            },
            &[],
            TcpFlags {
                rst: true,
                ack: true,
                ..TcpFlags::default()
            },
            None,
            0,
        )
    }

    fn build_tcp_frame(
        &mut self,
        key: FlowKey,
        plan: SendPlan,
        payload: &[u8],
        flags: TcpFlags,
        mss: Option<u16>,
        window: u16,
    ) -> Result<PooledFrame, Error> {
        let mut frame = self.acquire_frame()?;
        let payload_offset = Self::tcp_payload_offset(key, mss);
        let frame_len = payload_offset + payload.len();
        if frame_len > FRAME_CAPACITY {
            self.release_frame(frame);
            return Err(Error::Invariant("TCP frame exceeds buffer capacity"));
        }
        frame.buffer.writable()[payload_offset..frame_len].copy_from_slice(payload);
        let spec = TcpFrameSpec {
            key,
            plan,
            flags,
            mss,
            window,
            payload_len: payload.len(),
        };
        if let Err(error) = self.finalize_tcp_frame(&mut frame, spec) {
            self.release_frame(frame);
            return Err(error);
        }
        Ok(frame)
    }

    fn acquire_frame(&mut self) -> Result<PooledFrame, Error> {
        self.frame_pool
            .acquire()
            .map(|(pool_index, buffer)| PooledFrame { pool_index, buffer })
            .ok_or(Error::Invariant("TAP frame pool exhausted"))
    }

    fn release_frame(&mut self, frame: PooledFrame) {
        self.frame_pool.release(frame.pool_index, frame.buffer);
    }

    fn tcp_payload_offset(key: FlowKey, mss: Option<u16>) -> usize {
        let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
        let tcp_header_len = if mss.is_some() { 24 } else { 20 };
        ethernet::ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len
    }

    fn finalize_tcp_frame(&self, frame: &mut PooledFrame, spec: TcpFrameSpec) -> Result<(), Error> {
        let TcpFrameSpec {
            key,
            plan,
            flags,
            mss,
            window,
            payload_len,
        } = spec;
        let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
        let payload_offset = Self::tcp_payload_offset(key, mss);
        let frame_len = payload_offset + payload_len;
        let bytes = frame.buffer.writable();
        ethernet::write_header(
            bytes,
            self.config.target_mac,
            self.config.gateway_mac,
            if key.target.is_ipv4() {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
        )?;
        let ip_offset = ethernet::ETHERNET_HEADER_LEN;
        let tcp_offset = ip_offset + ip_header_len;
        let written = tcp::write_header(
            &mut bytes[tcp_offset..frame_len],
            TcpHeaderSpec {
                source_port: key.target.port(),
                destination_port: key.namespace.port(),
                sequence: plan.sequence,
                acknowledgment: plan.acknowledgment,
                flags,
                window,
                mss,
            },
        )?;
        match (key.target.ip(), key.namespace.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                ip::write_ipv4_header(
                    &mut bytes[ip_offset..frame_len],
                    source.octets(),
                    destination.octets(),
                    ip::IPPROTO_TCP,
                    written + payload_len,
                    0,
                )?;
                tcp::set_ipv4_checksum(
                    &mut bytes[tcp_offset..frame_len],
                    source.octets(),
                    destination.octets(),
                )?;
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                ip::write_ipv6_header(
                    &mut bytes[ip_offset..frame_len],
                    source.octets(),
                    destination.octets(),
                    ip::IPPROTO_TCP,
                    written + payload_len,
                )?;
                tcp::set_ipv6_checksum(
                    &mut bytes[tcp_offset..frame_len],
                    source.octets(),
                    destination.octets(),
                )?;
            }
            _ => return Err(Error::Invariant("mixed address families in flow")),
        }
        frame.buffer.set_len(frame_len);
        Ok(())
    }

    fn send_reset_for_flow(&mut self, id: FlowId) -> Result<(), Error> {
        let entry = self.flows.get(id).expect("flow exists");
        let frame = self.build_reset(entry.flow.key(), entry.flow.namespace_ack())?;
        self.metrics.tcp_resets += 1;
        self.queue_tap(None, frame, None)
    }

    fn queue_tap(
        &mut self,
        flow: Option<FlowId>,
        frame: PooledFrame,
        plan: Option<SendPlan>,
    ) -> Result<(), Error> {
        if self.tap_queue.is_empty()
            && plan.is_some_and(|plan| plan.length > 0)
            && self.test_drop_tcp_data > 0
        {
            self.test_drop_tcp_data -= 1;
            self.commit_tap_send(flow, frame, plan)?;
            return Ok(());
        }
        if self.tap_queue.is_empty() {
            match yayatht_sys::reactor::write(self.tap.as_raw_fd(), frame.buffer.bytes()) {
                Ok(written) if written == frame.buffer.bytes().len() => {
                    self.metrics.tap_tx_packets += 1;
                    self.commit_tap_send(flow, frame, plan)?;
                    return Ok(());
                }
                Ok(_) => {
                    self.release_frame(frame);
                    return Err(Error::Invariant("short TAP frame write"));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    self.release_frame(frame);
                    return Err(error.into());
                }
            }
        }
        self.tap_queue.push_back(QueuedFrame { flow, frame, plan });
        self.update_tap_interest()?;
        Ok(())
    }

    fn flush_tap_queue(&mut self) -> Result<(), Error> {
        for _ in 0..TAP_TX_BUDGET {
            let Some(frame) = self.tap_queue.pop_front() else {
                break;
            };
            match yayatht_sys::reactor::write(self.tap.as_raw_fd(), frame.frame.buffer.bytes()) {
                Ok(written) if written == frame.frame.buffer.bytes().len() => {
                    self.metrics.tap_tx_packets += 1;
                    self.commit_tap_send(frame.flow, frame.frame, frame.plan)?;
                }
                Ok(_) => {
                    self.release_frame(frame.frame);
                    return Err(Error::Invariant("short TAP frame write"));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.tap_queue.push_front(frame);
                    break;
                }
                Err(error) => {
                    self.release_frame(frame.frame);
                    return Err(error.into());
                }
            }
        }
        self.update_tap_interest()?;
        Ok(())
    }

    fn update_tap_interest(&self) -> Result<(), Error> {
        let mut events = 0;
        if self.frame_pool.available() > 0 {
            events |= yayatht_sys::reactor::READABLE;
        }
        if !self.tap_queue.is_empty() {
            events |= yayatht_sys::reactor::WRITABLE;
        }
        if events == 0 {
            return Err(Error::Invariant("TAP has neither read nor write capacity"));
        }
        self.epoll.modify(
            self.tap.as_raw_fd(),
            events,
            EpollToken::global(Resource::Tap).raw(),
        )?;
        Ok(())
    }

    fn commit_tap_send(
        &mut self,
        flow: Option<FlowId>,
        frame: PooledFrame,
        plan: Option<SendPlan>,
    ) -> Result<(), Error> {
        if let (Some(id), Some(plan)) = (flow, plan) {
            let entry = self
                .flows
                .get_mut(id)
                .ok_or(Error::Invariant("flow closed before TAP commit"))?;
            if plan.length > 0 || plan.fin {
                entry.flow.commit_send(plan);
            }
            let sequence_len = sequence::distance(plan.sequence, entry.flow.local_next());
            let expected = plan.length as u32 + u32::from(plan.syn) + u32::from(plan.fin);
            if sequence_len != expected || expected == 0 {
                return Err(Error::Invariant(
                    "TAP transmission sequence commitment mismatch",
                ));
            }
            entry.sent_segments.push_back(SentSegment {
                sequence: plan.sequence,
                payload_len: plan.length,
                syn: plan.syn,
                fin: plan.fin,
                last_sent: Instant::now(),
                retransmit_timeout: RETRANSMIT_INITIAL,
                retries: 0,
            });
        }
        self.release_frame(frame);
        Ok(())
    }

    fn close_flow(&mut self, id: FlowId) -> Result<(), Error> {
        let Some(entry) = self.flows.get(id) else {
            return Ok(());
        };
        let fd = entry.socket.as_raw_fd();
        let key = entry.flow.key();
        self.epoll.delete(fd)?;
        self.by_key.remove(&key);
        let mut retained = VecDeque::with_capacity(self.tap_queue.len());
        while let Some(frame) = self.tap_queue.pop_front() {
            if frame.flow == Some(id) {
                self.release_frame(frame.frame);
            } else {
                retained.push_back(frame);
            }
        }
        self.tap_queue = retained;
        self.update_tap_interest()?;
        self.flows.get_mut(id).expect("flow exists").flow.close();
        self.flows.defer_remove(id);
        Ok(())
    }

    fn cleanup_closed(&mut self) {
        let removed = self.flows.flush_deferred();
        self.metrics.tcp_closed += removed.len() as u64;
    }
}

fn test_drop_tcp_data_count() -> usize {
    #[cfg(debug_assertions)]
    {
        std::env::var(TEST_DROP_TCP_DATA_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = TEST_DROP_TCP_DATA_ENV;
        0
    }
}

pub fn run(config: Config, tap: OwnedFd, control: OwnedFd) -> Result<Metrics, Error> {
    Reactor::new(config, tap, control)?.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(sequence: u32, payload_len: usize, syn: bool, fin: bool) -> SentSegment {
        SentSegment {
            sequence,
            payload_len,
            syn,
            fin,
            last_sent: Instant::now(),
            retransmit_timeout: RETRANSMIT_INITIAL,
            retries: 0,
        }
    }

    #[test]
    fn partial_ack_trims_wrapped_segment() {
        let mut segment = segment(u32::MAX - 2, 5, false, false);
        assert!(!segment.acknowledge(0));
        assert_eq!(segment.sequence, 0);
        assert_eq!(segment.payload_len, 2);
        assert!(segment.acknowledge(2));
    }

    #[test]
    fn acknowledgment_accounts_for_syn_and_fin_sequence_space() {
        let mut syn = segment(100, 0, true, false);
        assert!(syn.acknowledge(101));

        let mut data_fin = segment(200, 3, false, true);
        assert!(!data_fin.acknowledge(203));
        assert_eq!(data_fin.sequence, 203);
        assert_eq!(data_fin.payload_len, 0);
        assert!(data_fin.fin);
        assert!(data_fin.acknowledge(204));
    }

    #[test]
    fn pending_socket_queue_enforces_its_byte_limit() {
        let mut queue = PendingSocketQueue::new(5);
        queue.push(b"abc").unwrap();
        assert_eq!(queue.remaining(), 2);
        assert_eq!(queue.push(b"def"), Err(()));
        queue.consume(2);
        assert_eq!(queue.front(), Some(b"c".as_slice()));
        queue.push(b"de").unwrap();
        queue.consume(1);
        queue.consume(2);
        assert!(queue.is_empty());
        assert_eq!(queue.remaining(), 5);
    }

    #[test]
    fn zero_window_probe_uses_bounded_exponential_backoff() {
        let now = Instant::now();
        let mut probe = ZeroWindowProbe::new(now);
        assert_eq!(probe.deadline, now + Duration::from_secs(1));
        probe.advance(now);
        assert_eq!(probe.interval, Duration::from_secs(2));
        probe.advance(now);
        probe.advance(now);
        probe.advance(now);
        assert_eq!(probe.interval, ZERO_WINDOW_PROBE_MAX);
        assert_eq!(probe.deadline, now + ZERO_WINDOW_PROBE_MAX);
    }
}
