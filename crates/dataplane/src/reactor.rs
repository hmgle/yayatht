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
use yayatht_tcp_adapter::flow::{Flow, FlowKey, ReceiveDisposition, SendPlan, State};
use yayatht_tcp_adapter::sequence;

const TAP_BUDGET: usize = 32;
const EVENT_CAPACITY: usize = 128;
const RETRANSMIT_INITIAL: Duration = Duration::from_secs(1);
const MAX_RETRIES: u8 = 5;
const PROXY_RESPONSE_CAPACITY: usize = 8 * 1024;

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
    socket: OwnedFd,
    transport_connected: bool,
    handshake: Option<Handshake>,
    pending_socket: VecDeque<Vec<u8>>,
    pending_shutdown: bool,
    sent_segments: VecDeque<SentSegment>,
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
    bytes: Vec<u8>,
    plan: Option<SendPlan>,
}

pub struct Reactor {
    config: Config,
    tap: OwnedFd,
    control: OwnedFd,
    epoll: yayatht_sys::reactor::Epoll,
    timer: yayatht_sys::reactor::TimerFd,
    flows: FlowTable<FlowEntry>,
    by_key: HashMap<FlowKey, FlowId>,
    tap_queue: VecDeque<QueuedFrame>,
    metrics: Metrics,
    shutting_down: bool,
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
            tap_queue: VecDeque::new(),
            metrics: Metrics::default(),
            shutting_down: false,
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
        let mut frame = vec![0u8; 64];
        let length = neighbor::write_arp_reply(
            &mut frame,
            self.config.gateway_mac,
            gateway.octets(),
            request,
        )?;
        frame.truncate(length);
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
            let mut frame = vec![0u8; 128];
            let length = neighbor::write_neighbor_advertisement(
                &mut frame,
                self.config.gateway_mac,
                ethernet.source(),
                gateway.octets(),
                packet.source(),
            )?;
            frame.truncate(length);
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
        let target = self.transport_target(key.target);
        let (socket, connected) = match yayatht_sys::socket::connect_nonblocking(target) {
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
        let entry = FlowEntry {
            flow: Flow::new(
                key,
                segment.sequence(),
                u32::from_ne_bytes(random),
                segment.mss().unwrap_or(default_mss),
            ),
            socket,
            transport_connected: false,
            handshake: self.proxy_handshake(key.target),
            pending_socket: VecDeque::new(),
            pending_shutdown: false,
            sent_segments: VecDeque::new(),
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
            ReceiveDisposition::Duplicate | ReceiveDisposition::OutOfOrder => self.send_ack(id)?,
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
                        .push_back(payload[sent..].to_vec());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.flows
                    .get_mut(id)
                    .expect("flow exists")
                    .pending_socket
                    .push_back(payload.to_vec());
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
            let Some(mut bytes) = self
                .flows
                .get_mut(id)
                .expect("flow exists")
                .pending_socket
                .pop_front()
            else {
                break;
            };
            let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
            match yayatht_sys::socket::send(fd, &bytes) {
                Ok(sent) => {
                    self.flows
                        .get_mut(id)
                        .expect("flow exists")
                        .flow
                        .record_upstream_submitted(sent);
                    if sent < bytes.len() {
                        bytes.drain(..sent);
                        self.flows
                            .get_mut(id)
                            .expect("flow exists")
                            .pending_socket
                            .push_front(bytes);
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.flows
                        .get_mut(id)
                        .expect("flow exists")
                        .pending_socket
                        .push_front(bytes);
                    break;
                }
                Err(error) => return Err(error.into()),
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
        if advanced {
            self.send_ack(id)?;
        }
        Ok(())
    }

    fn send_socket_data(&mut self, id: FlowId) -> Result<(), Error> {
        if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
            return Ok(());
        }
        let (state, payload_offset, window, mss, fd) = {
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
                entry.socket.as_raw_fd(),
            )
        };
        if !matches!(state, State::Established | State::NamespaceFinReceived) {
            return Ok(());
        }
        if window == 0 {
            return Ok(());
        }
        let offset = i32::try_from(payload_offset)
            .map_err(|_| Error::Invariant("socket peek offset exceeds i32"))?;
        yayatht_sys::tcp_info::set_peek_offset(fd, offset)?;
        let mut payload = vec![0u8; mss.min(window)];
        match yayatht_sys::socket::peek(fd, &mut payload) {
            Ok(0) => {
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
            Ok(length) => {
                payload.truncate(length);
                let plan = self
                    .flows
                    .get(id)
                    .expect("flow exists")
                    .flow
                    .plan_send(length, false)
                    .ok_or(Error::Invariant("unable to plan TCP payload"))?;
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
                self.queue_tap(Some(id), frame, Some(plan))?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
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
            let retransmit = {
                let entry = self.flows.get(id).expect("flow exists");
                entry.sent_segments.front().is_some_and(|segment| {
                    now.duration_since(segment.last_sent) >= segment.retransmit_timeout
                })
            };
            if !retransmit {
                continue;
            }
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
        Ok(())
    }

    fn retransmit_oldest(&mut self, id: FlowId, backoff: bool) -> Result<(), Error> {
        if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
            return Ok(());
        }
        let (segment, fd, acknowledgment) = {
            let entry = self.flows.get(id).expect("flow exists");
            let Some(segment) = entry.sent_segments.front() else {
                return Ok(());
            };
            (
                segment.clone(),
                entry.socket.as_raw_fd(),
                entry.flow.namespace_ack(),
            )
        };
        let mut payload = vec![0u8; segment.payload_len];
        if segment.payload_len > 0 {
            yayatht_sys::tcp_info::set_peek_offset(fd, 0)?;
            match yayatht_sys::socket::peek(fd, &mut payload) {
                Ok(length) if length == payload.len() => {}
                Ok(_) => {
                    self.fail_tcp_flow(id, "retained socket payload is shorter than segment")?;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.fail_tcp_flow(id, "retained socket payload is unavailable")?;
                    return Ok(());
                }
                Err(error) => {
                    self.fail_tcp_flow(id, &error.to_string())?;
                    return Ok(());
                }
            }
        }
        let plan = SendPlan {
            sequence: segment.sequence,
            acknowledgment,
            length: segment.payload_len,
            syn: segment.syn,
            fin: segment.fin,
        };
        let frame = self.build_flow_frame(id, plan, &payload, segment.flags())?;
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

    fn transport_target(&self, logical: SocketAddr) -> SocketAddr {
        match &self.config.upstream {
            Upstream::Proxy { address, .. } => *address,
            Upstream::Direct {
                host_loopback: false,
            } => logical,
            Upstream::Direct {
                host_loopback: true,
            } => match logical {
                SocketAddr::V4(address) if Some(*address.ip()) == self.config.gateway_ipv4 => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
                }
                SocketAddr::V6(address) if Some(*address.ip()) == self.config.gateway_ipv6 => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), address.port())
                }
                _ => logical,
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

    fn build_flow_frame(
        &self,
        id: FlowId,
        plan: SendPlan,
        payload: &[u8],
        flags: TcpFlags,
    ) -> Result<Vec<u8>, Error> {
        let flow = &self
            .flows
            .get(id)
            .ok_or(Error::Invariant("flow disappeared"))?
            .flow;
        self.build_tcp_frame(
            flow.key(),
            plan,
            payload,
            flags,
            flags.syn.then_some(flow.mss()),
        )
    }

    fn build_reset(&self, key: FlowKey, acknowledgment: u32) -> Result<Vec<u8>, Error> {
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
        )
    }

    fn build_tcp_frame(
        &self,
        key: FlowKey,
        plan: SendPlan,
        payload: &[u8],
        flags: TcpFlags,
        mss: Option<u16>,
    ) -> Result<Vec<u8>, Error> {
        let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
        let tcp_header_len = if mss.is_some() { 24 } else { 20 };
        let mut frame =
            vec![
                0u8;
                ethernet::ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len + payload.len()
            ];
        ethernet::write_header(
            &mut frame,
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
            &mut frame[tcp_offset..],
            TcpHeaderSpec {
                source_port: key.target.port(),
                destination_port: key.namespace.port(),
                sequence: plan.sequence,
                acknowledgment: plan.acknowledgment,
                flags,
                window: u16::MAX,
                mss,
            },
        )?;
        frame[tcp_offset + written..].copy_from_slice(payload);
        match (key.target.ip(), key.namespace.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                ip::write_ipv4_header(
                    &mut frame[ip_offset..],
                    source.octets(),
                    destination.octets(),
                    ip::IPPROTO_TCP,
                    written + payload.len(),
                    0,
                )?;
                tcp::set_ipv4_checksum(
                    &mut frame[tcp_offset..],
                    source.octets(),
                    destination.octets(),
                )?;
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                ip::write_ipv6_header(
                    &mut frame[ip_offset..],
                    source.octets(),
                    destination.octets(),
                    ip::IPPROTO_TCP,
                    written + payload.len(),
                )?;
                tcp::set_ipv6_checksum(
                    &mut frame[tcp_offset..],
                    source.octets(),
                    destination.octets(),
                )?;
            }
            _ => return Err(Error::Invariant("mixed address families in flow")),
        }
        Ok(frame)
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
        bytes: Vec<u8>,
        plan: Option<SendPlan>,
    ) -> Result<(), Error> {
        if self.tap_queue.is_empty() {
            match yayatht_sys::reactor::write(self.tap.as_raw_fd(), &bytes) {
                Ok(written) if written == bytes.len() => {
                    self.metrics.tap_tx_packets += 1;
                    self.commit_tap_send(flow, bytes, plan)?;
                    return Ok(());
                }
                Ok(_) => return Err(Error::Invariant("short TAP frame write")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.tap_queue.push_back(QueuedFrame { flow, bytes, plan });
        self.epoll.modify(
            self.tap.as_raw_fd(),
            yayatht_sys::reactor::READABLE | yayatht_sys::reactor::WRITABLE,
            EpollToken::global(Resource::Tap).raw(),
        )?;
        Ok(())
    }

    fn flush_tap_queue(&mut self) -> Result<(), Error> {
        while let Some(frame) = self.tap_queue.pop_front() {
            match yayatht_sys::reactor::write(self.tap.as_raw_fd(), &frame.bytes) {
                Ok(written) if written == frame.bytes.len() => {
                    self.metrics.tap_tx_packets += 1;
                    self.commit_tap_send(frame.flow, frame.bytes, frame.plan)?;
                }
                Ok(_) => return Err(Error::Invariant("short TAP frame write")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.tap_queue.push_front(frame);
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if self.tap_queue.is_empty() {
            self.epoll.modify(
                self.tap.as_raw_fd(),
                yayatht_sys::reactor::READABLE,
                EpollToken::global(Resource::Tap).raw(),
            )?;
        }
        Ok(())
    }

    fn commit_tap_send(
        &mut self,
        flow: Option<FlowId>,
        _bytes: Vec<u8>,
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
        self.tap_queue.retain(|frame| frame.flow != Some(id));
        if self.tap_queue.is_empty() {
            self.epoll.modify(
                self.tap.as_raw_fd(),
                yayatht_sys::reactor::READABLE,
                EpollToken::global(Resource::Tap).raw(),
            )?;
        }
        self.flows.get_mut(id).expect("flow exists").flow.close();
        self.flows.defer_remove(id);
        Ok(())
    }

    fn cleanup_closed(&mut self) {
        let removed = self.flows.flush_deferred();
        self.metrics.tcp_closed += removed.len() as u64;
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
}
