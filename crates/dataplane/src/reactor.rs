use crate::buffer::{BufferPool, FrameBuffer};
use crate::dns;
use crate::flow_table::{EpollToken, FlowId, FlowTable, Resource};
use getrandom::fill as random_fill;
use serde::Serialize;
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
use yayatht_packet::udp::{self, UdpDatagram};
use yayatht_packet::vnet;
use yayatht_proxy_proto::{Credentials, Handshake, Protocol};
use yayatht_tcp_adapter::flow::{
    ConstructionState, Flow, FlowConstruction, FlowInterface, FlowKey, FlowSide, FlowType,
    ReceiveDisposition, SendPlan, State,
};
use yayatht_tcp_adapter::sequence;

const TAP_BUDGET: usize = 32;
const TAP_TX_BUDGET: usize = 32;
const TAP_FRAME_POOL_BYTES: usize = 16 * 1024 * 1024;
const TAP_FRAME_POOL_MAX_FRAMES: usize = 4096;
/// Byte budget of the TSO super-frame pool; at the maximum frame size
/// this yields 64 in-flight super-frames before sends degrade to
/// MTU-sized frames.
const TAP_GSO_POOL_BYTES: usize = 4 * 1024 * 1024;
const EVENT_CAPACITY: usize = 128;
const RETRANSMIT_INITIAL: Duration = Duration::from_secs(1);
// Periodic tick driving retransmissions, zero-window probes and the ACK
// watchdog that bounds recovery from a dropped TX ACK timestamp
// notification to about one interval instead of the namespace RTO.
const TIMER_INTERVAL: Duration = Duration::from_millis(100);
/// Largest L3 packet a TSO/GRO super-frame can carry: both IP length
/// fields are 16 bits wide.
const GSO_MAX_L3_BYTES: usize = 65_535;
/// Window-scale shift offered on the SYN-ACK when the namespace SYN offers
/// the option. Shift 7 allows advertising up to ~8 MiB.
const WINDOW_SCALE_SHIFT: u8 = 7;
/// RFC 7323 caps the usable window-scale shift at 14.
const MAX_PEER_WINDOW_SHIFT: u8 = 14;
const MAX_RETRIES: u8 = 5;
const ZERO_WINDOW_PROBE_INITIAL: Duration = Duration::from_secs(1);
const ZERO_WINDOW_PROBE_MAX: Duration = Duration::from_secs(8);
const PROXY_RESPONSE_CAPACITY: usize = 8 * 1024;
const MAX_PENDING_SOCKET_BYTES: usize = 256 * 1024;
/// Socket buffers for the single DNS resolver connection.
const DNS_SOCKET_BUFFER_BYTES: usize = 64 * 1024;
/// Bound on length-prefixed queries queued toward the resolver; overflow
/// answers the query SERVFAIL instead of growing without limit.
const DNS_WRITE_BUFFER_LIMIT: usize = 64 * 1024;
/// Bound on the buffered upstream response stream (one maximum frame plus
/// its length prefix, with read-chunk slack).
const DNS_READ_BUFFER_LIMIT: usize = 128 * 1024;
/// Close the resolver connection after this quiet period with no
/// outstanding transactions (design §7: DNS flow idle timeout).
const DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const TEST_DNS_QUERY_TIMEOUT_MS_ENV: &str = "YAYATHT_TEST_DNS_QUERY_TIMEOUT_MS";
const TEST_DROP_TCP_DATA_ENV: &str = "YAYATHT_TEST_DROP_TCP_DATA";
const TEST_DROP_TCP_RETRANSMIT_ENV: &str = "YAYATHT_TEST_DROP_TCP_RETRANSMIT";
const TEST_DROP_TCP_SYN_ACK_ENV: &str = "YAYATHT_TEST_DROP_TCP_SYN_ACK";
const TEST_DROP_TCP_FIN_ENV: &str = "YAYATHT_TEST_DROP_TCP_FIN";
const TEST_DROP_TCP_ACK_ENV: &str = "YAYATHT_TEST_DROP_TCP_ACK";
const TEST_DROP_TCP_FIN_ACK_ENV: &str = "YAYATHT_TEST_DROP_TCP_FIN_ACK";
const TEST_LOCAL_ISN_ENV: &str = "YAYATHT_TEST_LOCAL_ISN";
const TEST_SUPPRESS_EVENT_ACK_REFRESH_ENV: &str = "YAYATHT_TEST_SUPPRESS_EVENT_ACK_REFRESH";

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
    pub tap_mtu: u32,
    pub tap_offload: bool,
    pub upstream: Upstream,
    /// Intercept gateway-directed 53/UDP and 53/TCP (design §9 `proxy-tcp`).
    pub dns_proxy_tcp: bool,
    /// Resolver behind the interception; `None` answers SERVFAIL/RST so a
    /// host without a usable resolver stays leak-free without failing
    /// TCP-only workloads.
    pub dns_upstream: Option<SocketAddr>,
    pub max_tcp_flows: usize,
    pub max_pending_tcp_bytes: usize,
    pub max_retained_tcp_bytes: usize,
    pub tcp_receive_buffer_bytes: usize,
    pub tcp_send_buffer_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
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
    /// Gateway DNS attempts refused because no resolver is configured.
    pub dns_refused: u64,
    /// Intercepted namespace UDP queries.
    pub dns_queries: u64,
    /// Resolver responses relayed back into the namespace.
    pub dns_responses: u64,
    /// Locally synthesized SERVFAIL/FORMERR answers.
    pub dns_failures: u64,
    /// Responses truncated with TC for the client's UDP capacity.
    pub dns_truncated: u64,
    /// Resolver TCP connections opened.
    pub dns_upstream_connects: u64,
    /// Unparsable intercepted DNS messages dropped without an answer.
    pub dns_dropped: u64,
    /// DNS replies dropped because the TAP frame pool was exhausted. The
    /// client retransmits, so a lost UDP answer is harmless -- unlike a
    /// propagated error, which would tear down the reactor.
    pub dns_reply_drops: u64,
    pub tx_ack_watchdog_advances: u64,
    pub tx_ack_watchdog_tail_recoveries: u64,
    pub active_tcp_flows: u64,
    pub peak_tcp_flows: u64,
    pub pending_tcp_bytes: u64,
    pub peak_pending_tcp_bytes: u64,
    pub max_pending_tcp_bytes: u64,
    pub retained_tcp_bytes: u64,
    pub peak_retained_tcp_bytes: u64,
    pub max_retained_tcp_bytes: u64,
    pub pending_limit_hits: u64,
    pub retained_limit_hits: u64,
    pub pending_high_water_events: u64,
    pub frame_pool_exhaustions: u64,
    pub tap_mtu: u64,
    pub tap_offload: u64,
    pub gso_frames_rx: u64,
    pub gso_frames_tx: u64,
    pub gso_pool_exhaustions: u64,
    pub tap_frame_capacity: u64,
    pub tap_frame_pool_frames: u64,
    pub tap_frame_pool_bytes: u64,
    pub zero_window_events: u64,
    pub zero_window_flows: u64,
    pub peak_zero_window_flows: u64,
    pub socket_receive_buffer_bytes: u64,
    pub peak_socket_receive_buffer_bytes: u64,
    pub socket_send_buffer_bytes: u64,
    pub peak_socket_send_buffer_bytes: u64,
    pub max_socket_buffer_bytes: u64,
    pub flow_fd_limit: u64,
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
    armed_socket_interest: u32,
    handshake: Option<Handshake>,
    pending_socket: PendingSocketQueue,
    pending_shutdown: bool,
    sent_segments: VecDeque<SentSegment>,
    upstream_window_clamp: Option<u32>,
    zero_window_probe: Option<ZeroWindowProbe>,
    last_namespace_byte: Option<u8>,
    socket_receive_buffer_bytes: usize,
    socket_send_buffer_bytes: usize,
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

    fn consume(&mut self, length: usize) -> usize {
        let Some(front) = self.chunks.front_mut() else {
            return 0;
        };
        let length = length.min(front.len());
        front.drain(..length);
        self.bytes -= length;
        if front.is_empty() {
            self.chunks.pop_front();
        }
        length
    }

    fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.bytes)
    }

    fn len(&self) -> usize {
        self.bytes
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

    fn record_timeout_retransmit(&mut self, now: Instant) {
        self.last_sent = now;
        self.retries = self.retries.saturating_add(1);
        self.retransmit_timeout = (self.retransmit_timeout * 2).min(Duration::from_secs(8));
    }

    fn retries_exhausted(&self) -> bool {
        self.retries >= MAX_RETRIES
    }
}

struct QueuedFrame {
    flow: Option<FlowId>,
    frame: PooledFrame,
    plan: Option<SendPlan>,
    reserved_retained: usize,
}

/// Which fixed pool a frame belongs to: MTU-sized frames for regular
/// traffic or the small pool of maximum-size TSO super-frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameTier {
    Mtu,
    Gso,
}

struct PooledFrame {
    tier: FrameTier,
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
    window_scale: Option<u8>,
    window: u16,
    payload_len: usize,
    /// Segment size the kernel splits the frame into when the payload
    /// exceeds it; `None` on frames that must never carry GSO state.
    gso_size: Option<u16>,
}

/// The single resolver connection behind DNS interception. It never
/// carries flow traffic, reconnects on demand, and closes after an idle
/// period; dropping the descriptor also clears its epoll registration.
enum DnsConnection {
    Idle,
    Connecting {
        socket: OwnedFd,
        connected: bool,
        handshake: Option<Handshake>,
    },
    Ready {
        socket: OwnedFd,
    },
}

impl DnsConnection {
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        match self {
            Self::Idle => None,
            Self::Connecting { socket, .. } | Self::Ready { socket } => Some(socket.as_raw_fd()),
        }
    }
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
    /// Pool of maximum-size frames for TSO sends; empty without offload.
    gso_pool: BufferPool,
    /// Capacity of an MTU-tier frame, the boundary for tier selection.
    mtu_frame_capacity: usize,
    tap_rx_buffer: Vec<u8>,
    tap_queue: VecDeque<QueuedFrame>,
    /// Length of the `virtio_net_hdr` prefix on every TAP read and write;
    /// zero when the TAP was opened without `IFF_VNET_HDR`.
    vnet_len: usize,
    metrics: Metrics,
    shutting_down: bool,
    test_drop_tcp_data: usize,
    test_drop_tcp_retransmit: usize,
    test_drop_tcp_syn_ack: usize,
    test_drop_tcp_fin: usize,
    test_drop_tcp_ack: usize,
    test_drop_tcp_fin_ack: usize,
    test_suppress_event_ack_refresh: usize,
    test_local_isn: Option<u32>,
    pending_socket_bytes: usize,
    retained_socket_bytes: usize,
    pending_pressure: bool,
    pending_pressure_dirty: bool,
    /// Flows whose upstream ACK state needs one refresh after the current
    /// TAP batch, instead of one refresh per received segment.
    ack_refresh_queue: Vec<FlowId>,
    timer_cursor_slot: u32,
    dns_engine: dns::Engine,
    dns_connection: DnsConnection,
    /// Length-prefixed queries waiting for the resolver stream.
    dns_write_buffer: VecDeque<u8>,
    /// Reassembly buffer for the length-prefixed response stream.
    dns_read_buffer: Vec<u8>,
    dns_last_activity: Instant,
}

impl Reactor {
    pub fn new(config: Config, tap: OwnedFd, control: OwnedFd) -> Result<Self, Error> {
        let epoll = yayatht_sys::reactor::Epoll::new()?;
        let timer = yayatht_sys::reactor::TimerFd::periodic(TIMER_INTERVAL)?;
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
        let vnet_len = if config.tap_offload {
            vnet::VNET_HEADER_LEN
        } else {
            0
        };
        let frame_capacity = usize::try_from(config.tap_mtu)
            .map_err(|_| Error::Invariant("TAP MTU exceeds usize"))?
            .checked_add(ethernet::ETHERNET_HEADER_LEN + vnet_len)
            .ok_or(Error::Invariant("TAP frame capacity overflow"))?;
        let frame_pool_frames =
            (TAP_FRAME_POOL_BYTES / frame_capacity).clamp(1, TAP_FRAME_POOL_MAX_FRAMES);
        let metrics = Metrics {
            max_pending_tcp_bytes: config.max_pending_tcp_bytes as u64,
            max_retained_tcp_bytes: config.max_retained_tcp_bytes as u64,
            flow_fd_limit: yayatht_sys::resource::dataplane_nofile_limit(max_tcp_flows)?,
            tap_mtu: u64::from(config.tap_mtu),
            tap_offload: u64::from(config.tap_offload),
            tap_frame_capacity: frame_capacity as u64,
            tap_frame_pool_frames: frame_pool_frames as u64,
            tap_frame_pool_bytes: frame_pool_frames.saturating_mul(frame_capacity) as u64,
            max_socket_buffer_bytes: u64::try_from(max_tcp_flows)
                .unwrap_or(u64::MAX)
                .saturating_mul(
                    u64::try_from(
                        config
                            .tcp_receive_buffer_bytes
                            .saturating_add(config.tcp_send_buffer_bytes),
                    )
                    .unwrap_or(u64::MAX),
                ),
            ..Metrics::default()
        };
        // Received frames may be GRO/TSO super-frames up to the 16-bit IP
        // length limit when offload is negotiated; TSO sends draw from a
        // dedicated pool of maximum-size frames.
        let gso_frame_capacity = vnet_len + ethernet::ETHERNET_HEADER_LEN + GSO_MAX_L3_BYTES;
        let tap_rx_capacity = if config.tap_offload {
            gso_frame_capacity
        } else {
            frame_capacity
        };
        let gso_pool_frames = if config.tap_offload {
            (TAP_GSO_POOL_BYTES / gso_frame_capacity).max(1)
        } else {
            0
        };
        Ok(Self {
            config,
            tap,
            control,
            epoll,
            timer,
            flows: FlowTable::with_capacity(max_tcp_flows),
            by_key: HashMap::with_capacity(max_tcp_flows),
            frame_pool: BufferPool::new(frame_pool_frames, frame_capacity),
            gso_pool: BufferPool::new(gso_pool_frames, gso_frame_capacity),
            mtu_frame_capacity: frame_capacity,
            tap_rx_buffer: vec![0; tap_rx_capacity],
            tap_queue: VecDeque::new(),
            vnet_len,
            metrics,
            shutting_down: false,
            test_drop_tcp_data: test_drop_tcp_data_count(),
            test_drop_tcp_retransmit: test_count(TEST_DROP_TCP_RETRANSMIT_ENV),
            test_drop_tcp_syn_ack: test_count(TEST_DROP_TCP_SYN_ACK_ENV),
            test_drop_tcp_fin: test_count(TEST_DROP_TCP_FIN_ENV),
            test_drop_tcp_ack: test_count(TEST_DROP_TCP_ACK_ENV),
            test_drop_tcp_fin_ack: test_count(TEST_DROP_TCP_FIN_ACK_ENV),
            test_suppress_event_ack_refresh: test_count(TEST_SUPPRESS_EVENT_ACK_REFRESH_ENV),
            test_local_isn: test_value(TEST_LOCAL_ISN_ENV),
            pending_socket_bytes: 0,
            retained_socket_bytes: 0,
            pending_pressure: false,
            pending_pressure_dirty: false,
            ack_refresh_queue: Vec::new(),
            timer_cursor_slot: 0,
            dns_engine: dns::Engine::with_query_timeout(
                test_value(TEST_DNS_QUERY_TIMEOUT_MS_ENV)
                    .map_or(dns::QUERY_TIMEOUT, Duration::from_millis),
            ),
            dns_connection: DnsConnection::Idle,
            dns_write_buffer: VecDeque::new(),
            dns_read_buffer: Vec::new(),
            dns_last_activity: Instant::now(),
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
                    (None, Resource::DnsUpstream) => self.handle_dns_upstream(event.events)?,
                    (Some(id), Resource::UpstreamSocket) => self.handle_socket(id, event.events)?,
                    _ => {}
                }
            }
            self.apply_pending_pressure()?;
            self.cleanup_closed()?;
            if self.shutting_down {
                for id in self.flows.active_ids() {
                    self.close_flow(id)?;
                }
            }
        }
        Ok(self.metrics)
    }

    fn handle_control(&mut self) -> Result<(), Error> {
        let mut message = [0u8; yayatht_sys::control::MAX_PAYLOAD + 20];
        match yayatht_sys::fdpass::recv_packet(self.control.as_raw_fd(), &mut message) {
            Ok(length) => {
                let message = yayatht_sys::control::decode(&message[..length])?;
                match message.kind {
                    yayatht_sys::control::Kind::Shutdown => self.shutting_down = true,
                    yayatht_sys::control::Kind::Status => {
                        let payload = serde_json::to_vec(&self.metrics)
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        let response = yayatht_sys::control::encode(
                            yayatht_sys::control::Kind::Status,
                            message.request_id,
                            &payload,
                        )?;
                        yayatht_sys::fdpass::send_packet(self.control.as_raw_fd(), &response)?;
                    }
                    _ => {}
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => self.shutting_down = true,
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn handle_tap(&mut self) -> Result<(), Error> {
        let mut bytes = std::mem::take(&mut self.tap_rx_buffer);
        let result = (|| {
            for _ in 0..TAP_BUDGET {
                if self.frame_pool.available() == 0 {
                    self.note_frame_pool_exhaustion();
                    self.update_tap_interest()?;
                    break;
                }
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
            self.flush_ack_refresh()
        })();
        self.tap_rx_buffer = bytes;
        result
    }

    fn handle_frame(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let (bytes, verify_checksum) = self.split_rx_vnet(bytes)?;
        let ethernet = EthernetFrame::parse(bytes)?;
        match ethernet.ether_type() {
            EtherType::Arp => self.handle_arp(ethernet),
            EtherType::Ipv4 => self.handle_ipv4(ethernet, verify_checksum),
            EtherType::Ipv6 => self.handle_ipv6(ethernet, verify_checksum),
            _ => Ok(()),
        }
    }

    /// Splits and validates the `virtio_net_hdr` prefix on a received TAP
    /// frame, returning the frame body and whether the transport checksum
    /// still needs software verification. With offload negotiated the
    /// namespace kernel hands over frames whose checksum is either already
    /// verified (`DATA_VALID`) or never computed (`NEEDS_CSUM`, pseudo
    /// sum only); both originate from the local kernel and skip
    /// verification. TSO super-frames carry a TCP GSO type and need no
    /// segmentation here -- the payload is forwarded to the upstream
    /// socket whole. UDP GSO types are not negotiated and drop as counted
    /// parse errors.
    fn split_rx_vnet<'a>(&mut self, bytes: &'a [u8]) -> Result<(&'a [u8], bool), Error> {
        if self.vnet_len == 0 {
            return Ok((bytes, true));
        }
        let header = vnet::VnetHeader::parse(bytes)?;
        match header.gso_type {
            vnet::GSO_NONE => {}
            vnet::GSO_TCPV4 | vnet::GSO_TCPV6 => self.metrics.gso_frames_rx += 1,
            _ => {
                return Err(Error::Invariant(
                    "TAP frame carries an unnegotiated GSO type",
                ));
            }
        }
        let verify_checksum = header.flags & (vnet::FLAG_NEEDS_CSUM | vnet::FLAG_DATA_VALID) == 0;
        Ok((&bytes[self.vnet_len..], verify_checksum))
    }

    fn handle_arp(&mut self, ethernet: EthernetFrame<'_>) -> Result<(), Error> {
        let Some(gateway) = self.config.gateway_ipv4 else {
            return Ok(());
        };
        let request = neighbor::parse_arp_request(ethernet.payload())?;
        if request.target_ip != gateway.octets() {
            return Ok(());
        }
        debug!(gateway = %gateway, "answering ARP request");
        let vnet_len = self.vnet_len;
        let mut frame = self.acquire_frame()?;
        let buffer = frame.buffer.writable();
        buffer[..vnet_len].fill(0);
        let length = match neighbor::write_arp_reply(
            &mut buffer[vnet_len..],
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
        frame.buffer.set_len(vnet_len + length);
        self.queue_tap(None, frame, None)
    }

    fn handle_ipv4(
        &mut self,
        ethernet: EthernetFrame<'_>,
        verify_checksum: bool,
    ) -> Result<(), Error> {
        let packet = Ipv4Packet::parse(ethernet.payload())?;
        if packet.protocol() == ip::IPPROTO_UDP {
            let datagram = UdpDatagram::parse_ipv4(packet, verify_checksum)?;
            let client = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(packet.source())),
                datagram.source_port(),
            );
            let gateway = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(packet.destination())),
                datagram.destination_port(),
            );
            return self.handle_udp(client, gateway, datagram.payload());
        }
        if packet.protocol() != ip::IPPROTO_TCP {
            return Ok(());
        }
        let segment = TcpSegment::parse_ipv4(packet, verify_checksum)?;
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

    fn handle_ipv6(
        &mut self,
        ethernet: EthernetFrame<'_>,
        verify_checksum: bool,
    ) -> Result<(), Error> {
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
            let vnet_len = self.vnet_len;
            let mut frame = self.acquire_frame()?;
            let buffer = frame.buffer.writable();
            buffer[..vnet_len].fill(0);
            let length = match neighbor::write_neighbor_advertisement(
                &mut buffer[vnet_len..],
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
            frame.buffer.set_len(vnet_len + length);
            debug!(gateway = %gateway, "sending neighbor advertisement");
            return self.queue_tap(None, frame, None);
        }
        if packet.next_header() == ip::IPPROTO_UDP {
            let datagram = UdpDatagram::parse_ipv6(packet, verify_checksum)?;
            let client = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(packet.source())),
                datagram.source_port(),
            );
            let gateway = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(packet.destination())),
                datagram.destination_port(),
            );
            return self.handle_udp(client, gateway, datagram.payload());
        }
        if packet.next_header() != ip::IPPROTO_TCP {
            return Ok(());
        }
        let segment = TcpSegment::parse_ipv6(packet, verify_checksum)?;
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
        debug!(namespace = %key.namespace, target = %key.target, "received namespace SYN");
        // Gateway-directed DNS keeps stream semantics but is retargeted at
        // the configured resolver (design §9 proxy-tcp). Without a usable
        // resolver the connection is refused rather than leaked.
        let logical_target = if self.dns_intercepts(key.target) {
            match self.config.dns_upstream {
                Some(resolver) => resolver,
                None => {
                    let frame = self.build_reset(key, segment.sequence().wrapping_add(1))?;
                    self.metrics.tcp_resets += 1;
                    self.metrics.dns_refused += 1;
                    return self.queue_tap(None, frame, None);
                }
            }
        } else {
            key.target
        };
        let (target_interface, transport_peer) = self.route_target(logical_target);
        let (socket, connected) = match yayatht_sys::socket::connect_nonblocking(
            transport_peer,
            self.config.tcp_receive_buffer_bytes,
            self.config.tcp_send_buffer_bytes,
        ) {
            Ok(result) => result,
            Err(_) => {
                let frame = self.build_reset(key, segment.sequence().wrapping_add(1))?;
                self.metrics.tcp_resets += 1;
                return self.queue_tap(None, frame, None);
            }
        };
        let target_side = FlowSide {
            interface: target_interface,
            local_endpoint: yayatht_sys::socket::local_address(socket.as_raw_fd())?,
            logical_peer: logical_target,
            transport_peer,
        };
        let (socket_receive_buffer_bytes, socket_send_buffer_bytes) =
            yayatht_sys::socket::socket_buffer_sizes(socket.as_raw_fd())?;
        let mut random = [0u8; 4];
        random_fill(&mut random)
            .map_err(|error| io::Error::other(format!("getrandom failed: {error:?}")))?;
        let ip_overhead: u32 = if key.target.is_ipv4() { 40 } else { 60 };
        let default_mss = u16::try_from(self.config.tap_mtu.saturating_sub(ip_overhead))
            .expect("validated TAP MTU produces a u16 MSS");
        let negotiated_mss = segment
            .mss()
            .filter(|mss| *mss >= 536)
            .unwrap_or(default_mss)
            .min(default_mss);
        // RFC 7323: scaling applies only when both SYNs carry the option.
        let (peer_window_shift, local_window_shift) = match segment.window_scale() {
            Some(shift) => (shift.min(MAX_PEER_WINDOW_SHIFT), WINDOW_SCALE_SHIFT),
            None => (0, 0),
        };
        let mut construction = FlowConstruction::new();
        construction
            .set_initiating(FlowSide {
                interface: FlowInterface::NamespaceTap,
                local_endpoint: key.target,
                logical_peer: key.namespace,
                transport_peer: key.namespace,
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
                segment.sequence(),
                self.test_local_isn
                    .unwrap_or_else(|| u32::from_ne_bytes(random)),
                negotiated_mss,
                peer_window_shift,
                local_window_shift,
            ),
            construction,
            socket,
            transport_connected: false,
            // The nonblocking connect is still in flight, so registration
            // below always starts with writable interest armed.
            armed_socket_interest: socket_interest(true, false, false),
            handshake: self.proxy_handshake(target_side.logical_peer),
            pending_socket: PendingSocketQueue::new(MAX_PENDING_SOCKET_BYTES),
            pending_shutdown: false,
            sent_segments: VecDeque::new(),
            upstream_window_clamp: None,
            zero_window_probe: None,
            last_namespace_byte: None,
            socket_receive_buffer_bytes,
            socket_send_buffer_bytes,
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
        self.metrics.active_tcp_flows += 1;
        self.metrics.peak_tcp_flows = self
            .metrics
            .peak_tcp_flows
            .max(self.metrics.active_tcp_flows);
        self.metrics.socket_receive_buffer_bytes += socket_receive_buffer_bytes as u64;
        self.metrics.peak_socket_receive_buffer_bytes = self
            .metrics
            .peak_socket_receive_buffer_bytes
            .max(self.metrics.socket_receive_buffer_bytes);
        self.metrics.socket_send_buffer_bytes += socket_send_buffer_bytes as u64;
        self.metrics.peak_socket_send_buffer_bytes = self
            .metrics
            .peak_socket_send_buffer_bytes
            .max(self.metrics.socket_send_buffer_bytes);
        let token = EpollToken::flow(id, Resource::UpstreamSocket, true)
            .ok_or(Error::Invariant("unable to encode flow token"))?;
        let fd = self
            .flows
            .get(id)
            .expect("inserted flow")
            .socket
            .as_raw_fd();
        let initial_interest = self
            .flows
            .get(id)
            .expect("inserted flow")
            .armed_socket_interest;
        self.epoll.add(fd, initial_interest, token.raw())?;
        self.flows
            .get_mut(id)
            .expect("inserted flow")
            .construction
            .activate()
            .map_err(|_| Error::Invariant("unable to activate TCP flow"))?;
        self.metrics.tcp_created += 1;
        // A loopback (or otherwise immediate) upstream handshake usually
        // completes inside the kernel before this handler returns, so a
        // zero-timeout probe finishes activation -- SYN-ACK or proxy
        // greeting -- in the same wakeup instead of paying a sleep/wake
        // round trip for the EPOLLOUT event. Slower targets stay fully
        // event-driven; a probed pending error takes the normal
        // finish_transport_connect failure path.
        let connected = connected || yayatht_sys::socket::poll_writable_now(fd)?;
        if connected {
            self.finish_transport_connect(id)?;
            self.update_socket_interest(id)?;
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
                self.release_retained_bytes(acked);
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
                if payload_len > 0 && !self.submit_namespace_payload(id, segment.payload())? {
                    return Ok(());
                }
                if fin {
                    let entry = self.flows.get_mut(id).expect("flow exists");
                    if entry.pending_socket.is_empty() {
                        yayatht_sys::socket::shutdown_write(entry.socket.as_raw_fd())?;
                    } else {
                        entry.pending_shutdown = true;
                    }
                    self.send_fin_ack(id)?;
                }
            }
            ReceiveDisposition::Duplicate
            | ReceiveDisposition::OutOfOrder
            | ReceiveDisposition::OutsideWindow => self.send_ack(id)?,
            ReceiveDisposition::Invalid => self.close_flow(id)?,
            ReceiveDisposition::Reset => {}
        }
        self.queue_ack_refresh(id);
        if self
            .flows
            .get(id)
            .is_some_and(|entry| entry.flow.state() == State::TimeWait)
        {
            self.close_flow(id)?;
        }
        Ok(())
    }

    /// Defers the upstream ACK refresh for `id` until the end of the current
    /// TAP batch, so a burst of segments costs one TCP_INFO query and one ACK
    /// instead of one per segment.
    fn queue_ack_refresh(&mut self, id: FlowId) {
        if !self.ack_refresh_queue.contains(&id) {
            self.ack_refresh_queue.push(id);
        }
    }

    fn flush_ack_refresh(&mut self) -> Result<(), Error> {
        while let Some(id) = self.ack_refresh_queue.pop() {
            if self.flow_is_closed(id) {
                continue;
            }
            if !self.consume_ack_refresh_suppression() {
                self.refresh_upstream_ack(id)?;
            }
            self.update_socket_interest(id)?;
        }
        Ok(())
    }

    /// Test-only injection that skips event-driven upstream ACK refreshes,
    /// leaving the timer watchdog as the sole ACK-progress path so tests
    /// can pin it deterministically. Always false outside debug builds.
    fn consume_ack_refresh_suppression(&mut self) -> bool {
        if self.test_suppress_event_ack_refresh > 0 {
            self.test_suppress_event_ack_refresh -= 1;
            true
        } else {
            false
        }
    }

    fn submit_namespace_payload(&mut self, id: FlowId, payload: &[u8]) -> Result<bool, Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        match yayatht_sys::socket::send(fd, payload) {
            Ok(sent) => {
                self.flows
                    .get_mut(id)
                    .expect("flow exists")
                    .flow
                    .record_upstream_submitted(sent);
                if sent < payload.len() && !self.enqueue_pending_payload(id, &payload[sent..])? {
                    return Ok(false);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if !self.enqueue_pending_payload(id, payload)? {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(true)
    }

    fn enqueue_pending_payload(&mut self, id: FlowId, payload: &[u8]) -> Result<bool, Error> {
        let flow_remaining = self
            .flows
            .get(id)
            .expect("flow exists")
            .pending_socket
            .remaining();
        let global_remaining = self
            .config
            .max_pending_tcp_bytes
            .saturating_sub(self.pending_socket_bytes);
        if payload.len() > flow_remaining || payload.len() > global_remaining {
            self.metrics.pending_limit_hits += 1;
            self.fail_tcp_flow(id, "TCP pending payload limit reached")?;
            return Ok(false);
        }
        self.flows
            .get_mut(id)
            .expect("flow exists")
            .pending_socket
            .push(payload)
            .map_err(|()| Error::Invariant("pending socket accounting mismatch"))?;
        self.pending_socket_bytes += payload.len();
        self.metrics.pending_tcp_bytes = self.pending_socket_bytes as u64;
        self.metrics.peak_pending_tcp_bytes = self
            .metrics
            .peak_pending_tcp_bytes
            .max(self.metrics.pending_tcp_bytes);
        self.update_pending_pressure_state();
        Ok(true)
    }

    fn consume_pending_payload(&mut self, id: FlowId, length: usize) -> usize {
        let consumed = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .pending_socket
            .consume(length);
        self.pending_socket_bytes = self.pending_socket_bytes.saturating_sub(consumed);
        self.metrics.pending_tcp_bytes = self.pending_socket_bytes as u64;
        self.update_pending_pressure_state();
        consumed
    }

    fn update_pending_pressure_state(&mut self) {
        let pressured = pending_pressure_state(
            self.pending_pressure,
            self.pending_socket_bytes,
            self.config.max_pending_tcp_bytes,
        );
        if pressured != self.pending_pressure {
            self.pending_pressure = pressured;
            self.pending_pressure_dirty = true;
            if pressured {
                self.metrics.pending_high_water_events += 1;
            }
        }
    }

    fn desired_socket_interest(entry: &FlowEntry) -> u32 {
        socket_interest(
            !entry.transport_connected,
            entry
                .handshake
                .as_ref()
                .is_some_and(|handshake| !handshake.output().is_empty()),
            !entry.pending_socket.is_empty(),
        )
    }

    fn update_socket_interest(&mut self, id: FlowId) -> Result<(), Error> {
        if self.flow_is_closed(id) {
            return Ok(());
        }
        let entry = self.flows.get(id).expect("flow exists");
        let desired = Self::desired_socket_interest(entry);
        if desired == entry.armed_socket_interest {
            return Ok(());
        }
        let token = EpollToken::flow(id, Resource::UpstreamSocket, true)
            .ok_or(Error::Invariant("unable to encode flow token"))?;
        self.epoll
            .modify(entry.socket.as_raw_fd(), desired, token.raw())?;
        self.flows
            .get_mut(id)
            .expect("flow exists")
            .armed_socket_interest = desired;
        Ok(())
    }

    fn handle_socket(&mut self, id: FlowId, events: u32) -> Result<(), Error> {
        self.handle_socket_events(id, events)?;
        self.update_socket_interest(id)
    }

    fn handle_socket_events(&mut self, id: FlowId, events: u32) -> Result<(), Error> {
        if self.flow_is_closed(id) {
            return Ok(());
        }
        if events & yayatht_sys::reactor::ERROR != 0 {
            let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
            if yayatht_sys::socket::pending_error(fd)?.is_some() {
                self.send_reset_for_flow(id)?;
                return self.close_flow(id);
            }
            // Level-triggered EPOLLERR persists until the error queue
            // is empty; the refresh below reads the acknowledged bytes.
            let drain = yayatht_sys::socket::drain_tx_timestamps(fd)?;
            if drain.foreign_errors > 0 {
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
        if !self.consume_ack_refresh_suppression() {
            self.refresh_upstream_ack(id)?;
        }
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
        // The Linux 6.6 baseline guarantees SO_PEEK_OFF, TX ACK timestamps
        // and a complete TCP_INFO; a socket that rejects them is broken, so
        // the flow fails instead of degrading. Timestamps are enabled before
        // any payload is submitted so every acknowledged send queues an
        // error-queue wakeup.
        if let Err(error) = yayatht_sys::tcp_info::set_peek_offset(fd, 0) {
            return self.fail_tcp_flow(id, &format!("SO_PEEK_OFF activation failed: {error}"));
        }
        if let Err(error) = yayatht_sys::socket::enable_tx_ack_timestamps(fd) {
            return self.fail_tcp_flow(id, &format!("TX ACK timestamps unavailable: {error}"));
        }
        let bytes_acked = match yayatht_sys::tcp_info::bytes_acked(fd) {
            Ok(bytes_acked) => bytes_acked,
            Err(error) => {
                return self.fail_tcp_flow(id, &format!("TCP_INFO unavailable: {error}"));
            }
        };
        self.update_namespace_window(id)?;
        let plan = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .socket_connected(bytes_acked);
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
        debug!(flow_slot = id.slot, "queueing SYN-ACK");
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
                    self.consume_pending_payload(id, sent);
                    self.flows
                        .get_mut(id)
                        .expect("flow exists")
                        .flow
                        .record_upstream_submitted(sent);
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

    /// Reads the upstream socket's acknowledgment progress and re-advertises
    /// the namespace window; returns whether the ACK point advanced.
    fn refresh_upstream_ack(&mut self, id: FlowId) -> Result<bool, Error> {
        let fd = self.flows.get(id).expect("flow exists").socket.as_raw_fd();
        let acknowledged = yayatht_sys::tcp_info::bytes_acked(fd)?;
        let advanced = self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .record_upstream_ack(acknowledged);
        let window_changed = self.update_namespace_window(id)?;
        if advanced || window_changed {
            self.send_ack(id)?;
        }
        Ok(advanced)
    }

    fn update_namespace_window(&mut self, id: FlowId) -> Result<bool, Error> {
        let entry = self.flows.get(id).expect("flow exists");
        // SO_SNDBUF is set explicitly at socket creation, so the capacity
        // captured at construction is fixed (the kernel reports it doubled
        // to cover bookkeeping overhead; the usable half matches what
        // setsockopt requested). Occupancy is submitted-minus-acknowledged
        // bytes: `upstream_acked` lags the kernel between TCP_INFO reads,
        // which can only shrink the advertised window, never inflate it.
        // Still-unacked proxy handshake bytes predate the accounting
        // baseline and are the one transient overestimate; any resulting
        // short write lands in the bounded pending queue.
        let socket_available = (entry.socket_send_buffer_bytes / 2)
            .saturating_sub(usize::try_from(entry.flow.upstream_unacked()).unwrap_or(usize::MAX));
        let queue_available = entry.pending_socket.remaining();
        let global_available = if self.pending_pressure {
            0
        } else {
            self.config
                .max_pending_tcp_bytes
                .saturating_sub(self.pending_socket_bytes)
        };
        // The upstream peer's receive window (tcpi_snd_wnd) is deliberately
        // NOT part of this bound. When the peer's window collapses, the send
        // buffer backs up and socket_available shrinks, so backpressure is
        // preserved -- but a peer-window bound could pin the advertised
        // window below one MSS while the socket buffer sits empty. The
        // namespace sender then defers per sender-side silly-window
        // avoidance, and because a pure upstream window update carries no
        // data and acknowledges no new bytes, no event wakes the reactor
        // until the namespace persist timer fires roughly 200 ms later.
        // Keeping the bound on buffer occupancy guarantees the window only
        // closes while acknowledgment (timestamp) wakeups are outstanding.
        let ack_window = entry.flow.max_advertised_window() as usize;
        let available = socket_available
            .min(queue_available)
            .min(global_available)
            .min(ack_window);
        let window = u32::try_from(available).unwrap_or(u32::MAX);
        Ok(self
            .flows
            .get_mut(id)
            .expect("flow exists")
            .flow
            .set_advertised_window(window))
    }

    fn apply_pending_pressure(&mut self) -> Result<(), Error> {
        if !self.pending_pressure_dirty {
            return Ok(());
        }
        self.pending_pressure_dirty = false;
        for id in self.flows.active_ids() {
            if self.flow_is_closed(id) {
                continue;
            }
            if self.frame_pool.available() == 0 {
                self.note_frame_pool_exhaustion();
                self.pending_pressure_dirty = true;
                break;
            }
            if self.update_namespace_window(id)? {
                self.send_ack(id)?;
            }
        }
        Ok(())
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
        yayatht_sys::tcp_info::set_window_clamp(fd, window.max(1))?;
        self.flows
            .get_mut(id)
            .expect("flow exists")
            .upstream_window_clamp = Some(window);
        Ok(())
    }

    fn refresh_zero_window_probe(&mut self, id: FlowId, now: Instant) {
        let transition = {
            let entry = self.flows.get_mut(id).expect("flow exists");
            let should_probe = entry.flow.peer_window() == 0
                && matches!(
                    entry.flow.state(),
                    State::Established | State::NamespaceFinReceived
                );
            match (entry.zero_window_probe.is_some(), should_probe) {
                (false, true) => {
                    entry.zero_window_probe = Some(ZeroWindowProbe::new(now));
                    1i8
                }
                (true, false) => {
                    entry.zero_window_probe = None;
                    -1
                }
                _ => 0,
            }
        };
        if transition > 0 {
            self.metrics.zero_window_events += 1;
            self.metrics.zero_window_flows += 1;
            self.metrics.peak_zero_window_flows = self
                .metrics
                .peak_zero_window_flows
                .max(self.metrics.zero_window_flows);
        } else if transition < 0 {
            self.metrics.zero_window_flows = self.metrics.zero_window_flows.saturating_sub(1);
        }
    }

    fn send_socket_data(&mut self, id: FlowId) -> Result<(), Error> {
        for _ in 0..TAP_TX_BUDGET {
            if self.frame_pool.available() == 0 {
                self.note_frame_pool_exhaustion();
                break;
            }
            if self.tap_queue.iter().any(|frame| frame.flow == Some(id)) {
                break;
            }
            let (state, payload_offset, window, mss, key) = {
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
                    entry
                        .construction
                        .active_sides()
                        .ok_or(Error::Invariant("inactive flow reached socket reader"))?
                        .namespace_key(),
                )
            };
            if !matches!(state, State::Established | State::NamespaceFinReceived) || window == 0 {
                break;
            }
            let retained_available = self
                .config
                .max_retained_tcp_bytes
                .saturating_sub(self.retained_socket_bytes);
            if retained_available == 0 {
                self.metrics.retained_limit_hits += 1;
                break;
            }
            // With offload one send may carry a TSO super-frame up to the
            // 16-bit IP length limit; the kernel segments it at the MSS.
            // Without offload each frame carries at most one MSS.
            let max_send = if self.vnet_len > 0 {
                let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
                GSO_MAX_L3_BYTES - ip_header_len - tcp::TCP_MIN_HEADER_LEN
            } else {
                mss
            };
            match self.peek_socket_frame(
                id,
                payload_offset,
                max_send.min(window).min(retained_available),
            )? {
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
                    let last_byte = frame.buffer.writable()
                        [self.tcp_payload_offset(key, None, None) + length - 1];
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
        self.send_ack_kind(id, false)
    }

    fn send_fin_ack(&mut self, id: FlowId) -> Result<(), Error> {
        self.send_ack_kind(id, true)
    }

    fn send_ack_kind(&mut self, id: FlowId, fin_ack: bool) -> Result<(), Error> {
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
        if fin_ack && self.test_drop_tcp_fin_ack > 0 {
            self.test_drop_tcp_fin_ack -= 1;
            self.release_frame(frame);
            return Ok(());
        }
        self.queue_tap(None, frame, Some(plan))
    }

    fn handle_timers(&mut self) -> Result<(), Error> {
        let now = Instant::now();
        self.handle_dns_timers(now)?;
        let ids = self.flows.active_ids();
        if ids.is_empty() {
            return Ok(());
        }
        // A frame-pool break abandons the rest of the scan, and active_ids
        // always returns ascending slots, so a fixed origin would starve
        // high slots under sustained exhaustion. Resume at the first
        // unprocessed flow's slot -- or its successor once that flow is
        // gone -- so churn between ticks cannot shift the origin onto
        // flows that were already served.
        let start = ids.partition_point(|id| id.slot < self.timer_cursor_slot) % ids.len();
        for offset in 0..ids.len() {
            let index = (start + offset) % ids.len();
            let id = ids[index];
            if self.frame_pool.available() == 0 {
                self.note_frame_pool_exhaustion();
                self.timer_cursor_slot = id.slot;
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
                    .is_some_and(SentSegment::retries_exhausted)
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
            self.watchdog_upstream_ack(id)?;
        }
        Ok(())
    }

    /// ACK-progress watchdog, run from the periodic timer for flows with
    /// unacknowledged upstream bytes. TX ACK timestamps normally drive the
    /// upstream ACK, but the kernel drops the error-queue message when the
    /// socket's receive accounting is full -- a normal state here, because
    /// namespace-bound data is parked in the receive queue for backpressure.
    /// While TAP frames are available, the tick bounds the recovery delay
    /// to about one timer interval instead of the namespace RTO.
    ///
    /// Any advance found by the timer counts as a watchdog advance; that
    /// includes the timer merely winning the race against a queued
    /// error-queue event, and partial acknowledgment of a large send whose
    /// timestamp legitimately fires only once its last byte is covered.
    /// An advance is counted as a tail recovery -- the calibration signal
    /// for genuine notification loss -- only when no silent explanation
    /// remains: the queue was empty before the refresh, the refresh left
    /// nothing unacknowledged (so the final send's timestamp must already
    /// have been generated), and a second drain still finds no
    /// acknowledgment. Mid-stream losses stay uncounted; a later
    /// acknowledgment or the next tick re-notifies those.
    fn watchdog_upstream_ack(&mut self, id: FlowId) -> Result<(), Error> {
        if self.frame_pool.available() == 0 || self.flow_is_closed(id) {
            return Ok(());
        }
        let (unacked, fd) = {
            let entry = self.flows.get(id).expect("flow exists");
            (entry.flow.upstream_unacked() > 0, entry.socket.as_raw_fd())
        };
        if !unacked {
            return Ok(());
        }
        let drain = yayatht_sys::socket::drain_tx_timestamps(fd)?;
        if drain.foreign_errors > 0 {
            self.send_reset_for_flow(id)?;
            return self.close_flow(id);
        }
        let notified = drain.acknowledgments > 0;
        let advanced = self.refresh_upstream_ack(id)?;
        if !advanced {
            return Ok(());
        }
        self.metrics.tx_ack_watchdog_advances += 1;
        if notified || self.flow_is_closed(id) {
            return Ok(());
        }
        if self
            .flows
            .get(id)
            .expect("flow exists")
            .flow
            .upstream_unacked()
            > 0
        {
            return Ok(());
        }
        // The acknowledgment behind this advance may have raced the first
        // drain: the kernel enqueues the timestamp while recording the
        // acknowledged bytes, so a queue that is still empty after the
        // advance was observed proves the notification was dropped.
        let redrain = yayatht_sys::socket::drain_tx_timestamps(fd)?;
        if redrain.foreign_errors > 0 {
            self.send_reset_for_flow(id)?;
            return self.close_flow(id);
        }
        if redrain.acknowledgments == 0 {
            self.metrics.tx_ack_watchdog_tail_recoveries += 1;
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
        let mut socket_byte = [0u8; 1];
        yayatht_sys::tcp_info::set_peek_offset(fd, 0)?;
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
        if self.test_drop_tcp_retransmit > 0 {
            self.test_drop_tcp_retransmit -= 1;
            self.release_frame(frame);
        } else {
            self.queue_tap(Some(id), frame, None)?;
        }
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
        let (segment, acknowledgment, key) = {
            let entry = self.flows.get(id).expect("flow exists");
            let Some(segment) = entry.sent_segments.front() else {
                return Ok(());
            };
            (
                segment.clone(),
                entry.flow.namespace_ack(),
                entry
                    .construction
                    .active_sides()
                    .ok_or(Error::Invariant("inactive flow reached retransmit"))?
                    .namespace_key(),
            )
        };
        let frame = if segment.payload_len > 0 {
            match self.peek_socket_frame(id, 0, segment.payload_len)? {
                PeekedFrame::Data { frame, length } => {
                    // A dry GSO pool can clamp the frame below a super-frame
                    // segment; retransmitting a prefix of the unacknowledged
                    // range is valid TCP and the cumulative ACK trims the
                    // rest. Falling short of both the segment and the frame
                    // capacity means retained socket data went missing.
                    let payload_capacity = frame
                        .buffer
                        .capacity()
                        .saturating_sub(self.tcp_payload_offset(key, None, None));
                    if length != segment.payload_len.min(payload_capacity) {
                        self.release_frame(frame);
                        self.fail_tcp_flow(id, "retained socket payload is shorter than segment")?;
                        return Ok(());
                    }
                    let truncated = length < segment.payload_len;
                    let plan = SendPlan {
                        sequence: segment.sequence,
                        acknowledgment,
                        length,
                        syn: segment.syn,
                        fin: segment.fin && !truncated,
                    };
                    let flags = TcpFlags {
                        syn: segment.syn,
                        fin: segment.fin && !truncated,
                        psh: true,
                        ack: true,
                        ..TcpFlags::default()
                    };
                    self.finalize_flow_payload_frame(id, frame, plan, flags, length)?
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
            let plan = SendPlan {
                sequence: segment.sequence,
                acknowledgment,
                length: 0,
                syn: segment.syn,
                fin: segment.fin,
            };
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
        if backoff {
            segment.record_timeout_retransmit(Instant::now());
        } else {
            segment.last_sent = Instant::now();
        }
        self.metrics.tcp_retransmits += 1;
        Ok(())
    }

    fn fail_tcp_flow(&mut self, id: FlowId, reason: &str) -> Result<(), Error> {
        warn!(%reason, "TCP flow invariant failed");
        self.send_reset_for_flow(id)?;
        self.close_flow(id)
    }

    /// Whether a namespace destination falls under DNS interception:
    /// gateway-directed port 53 with `proxy-tcp` mode active.
    fn dns_intercepts(&self, target: SocketAddr) -> bool {
        if !self.config.dns_proxy_tcp || target.port() != 53 {
            return false;
        }
        match target.ip() {
            IpAddr::V4(ip) => Some(ip) == self.config.gateway_ipv4,
            IpAddr::V6(ip) => Some(ip) == self.config.gateway_ipv6,
        }
    }

    /// Entry point for namespace UDP: gateway-directed DNS is intercepted,
    /// everything else is dropped exactly as before UDP parsing existed.
    fn handle_udp(
        &mut self,
        client: SocketAddr,
        gateway: SocketAddr,
        message: &[u8],
    ) -> Result<(), Error> {
        if !self.dns_intercepts(gateway) {
            return Ok(());
        }
        self.metrics.dns_queries += 1;
        let now = Instant::now();
        let resolver_available = self.config.dns_upstream.is_some();
        match self
            .dns_engine
            .accept_query(client, gateway, message, resolver_available, now)
        {
            dns::QueryDisposition::Drop => {
                self.metrics.dns_dropped += 1;
                Ok(())
            }
            dns::QueryDisposition::Respond(reply) => {
                self.metrics.dns_failures += 1;
                if !resolver_available {
                    self.metrics.dns_refused += 1;
                }
                self.queue_dns_reply(client, gateway, &reply)
            }
            dns::QueryDisposition::Forward { upstream_id } => {
                self.forward_dns_query(upstream_id, message)
            }
        }
    }

    /// Appends the query to the resolver stream under its rewritten ID and
    /// makes sure a connection is coming up to carry it.
    fn forward_dns_query(&mut self, upstream_id: u16, message: &[u8]) -> Result<(), Error> {
        let length = u16::try_from(message.len()).ok();
        let fits = length.is_some()
            && self.dns_write_buffer.len() + 2 + message.len() <= DNS_WRITE_BUFFER_LIMIT;
        if !fits {
            if let Some((transaction, reply)) = self.dns_engine.abort(upstream_id) {
                self.metrics.dns_failures += 1;
                self.queue_dns_reply(transaction.client, transaction.gateway, &reply)?;
            }
            return Ok(());
        }
        self.dns_write_buffer
            .extend(length.expect("checked above").to_be_bytes());
        self.dns_write_buffer.extend(upstream_id.to_be_bytes());
        self.dns_write_buffer.extend(message[2..].iter().copied());
        self.dns_last_activity = Instant::now();
        self.ensure_dns_connection()?;
        if matches!(self.dns_connection, DnsConnection::Ready { .. }) {
            self.flush_dns_write()?;
        }
        self.update_dns_interest()
    }

    /// Opens the resolver connection if none exists: through the proxy
    /// with a dedicated CONNECT tunnel targeting the resolver, or a direct
    /// host socket. Never shares a flow's tunnel.
    fn ensure_dns_connection(&mut self) -> Result<(), Error> {
        if !matches!(self.dns_connection, DnsConnection::Idle) {
            return Ok(());
        }
        let resolver = self
            .config
            .dns_upstream
            .ok_or(Error::Invariant("DNS forward without a resolver"))?;
        let (transport, handshake) = match &self.config.upstream {
            Upstream::Proxy {
                protocol,
                address,
                credentials,
            } => (
                *address,
                Some(Handshake::new(*protocol, resolver, credentials.clone())),
            ),
            Upstream::Direct { .. } => (resolver, None),
        };
        match yayatht_sys::socket::connect_nonblocking(
            transport,
            DNS_SOCKET_BUFFER_BYTES,
            DNS_SOCKET_BUFFER_BYTES,
        ) {
            Ok((socket, connected)) => {
                self.epoll.add(
                    socket.as_raw_fd(),
                    socket_interest(true, false, false),
                    EpollToken::global(Resource::DnsUpstream).raw(),
                )?;
                self.metrics.dns_upstream_connects += 1;
                self.dns_connection = DnsConnection::Connecting {
                    socket,
                    connected,
                    handshake,
                };
                Ok(())
            }
            Err(error) => {
                debug!(%error, "DNS resolver connect failed");
                self.fail_dns_connection()
            }
        }
    }

    fn handle_dns_upstream(&mut self, events: u32) -> Result<(), Error> {
        let Some(fd) = self.dns_connection.raw_fd() else {
            return Ok(());
        };
        if events & yayatht_sys::reactor::ERROR != 0
            && yayatht_sys::socket::pending_error(fd)?.is_some()
        {
            return self.fail_dns_connection();
        }
        if let DnsConnection::Connecting { connected, .. } = &mut self.dns_connection {
            if !*connected {
                if events & yayatht_sys::reactor::WRITABLE == 0 {
                    return Ok(());
                }
                if yayatht_sys::socket::pending_error(fd)?.is_some() {
                    return self.fail_dns_connection();
                }
                *connected = true;
            }
            self.drive_dns_handshake()?;
        }
        if let DnsConnection::Ready { .. } = self.dns_connection {
            if events & yayatht_sys::reactor::WRITABLE != 0 {
                self.flush_dns_write()?;
            }
            if events & (yayatht_sys::reactor::READABLE | yayatht_sys::reactor::READ_HANGUP) != 0
                && !self.read_dns_stream()?
            {
                return self.fail_dns_connection();
            }
        }
        if matches!(self.dns_connection, DnsConnection::Idle) {
            return Ok(());
        }
        self.update_dns_interest()
    }

    /// Drives the proxy CONNECT handshake on the connecting resolver
    /// socket; on completion promotes the connection and flushes queued
    /// queries. Stream bytes the proxy pipelined after its final reply
    /// stay in the socket for the Ready read path.
    fn drive_dns_handshake(&mut self) -> Result<(), Error> {
        loop {
            let DnsConnection::Connecting {
                socket, handshake, ..
            } = &mut self.dns_connection
            else {
                return Ok(());
            };
            let Some(pending) = handshake.as_mut() else {
                break;
            };
            if pending.is_complete() {
                break;
            }
            let fd = socket.as_raw_fd();
            while !pending.output().is_empty() {
                match yayatht_sys::socket::send(fd, pending.output()) {
                    Ok(0) => return self.fail_dns_connection(),
                    Ok(sent) => {
                        if pending.advance_output(sent).is_err() {
                            return self.fail_dns_connection();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(_) => return self.fail_dns_connection(),
                }
            }
            if !pending.wants_input() {
                continue;
            }
            let mut response = [0u8; PROXY_RESPONSE_CAPACITY];
            let length = match yayatht_sys::socket::peek(fd, &mut response) {
                Ok(0) => return self.fail_dns_connection(),
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return self.fail_dns_connection(),
            };
            match pending.receive(&response[..length]) {
                Ok(0) => return Ok(()),
                Ok(consumed) => {
                    if yayatht_sys::socket::discard(fd, consumed)? != consumed {
                        return self.fail_dns_connection();
                    }
                }
                Err(error) => {
                    debug!(%error, "DNS resolver proxy handshake failed");
                    return self.fail_dns_connection();
                }
            }
        }
        let DnsConnection::Connecting { socket, .. } =
            std::mem::replace(&mut self.dns_connection, DnsConnection::Idle)
        else {
            return Ok(());
        };
        self.dns_connection = DnsConnection::Ready { socket };
        self.flush_dns_write()
    }

    fn flush_dns_write(&mut self) -> Result<(), Error> {
        let DnsConnection::Ready { socket } = &self.dns_connection else {
            return Ok(());
        };
        let fd = socket.as_raw_fd();
        while !self.dns_write_buffer.is_empty() {
            let (chunk, _) = self.dns_write_buffer.as_slices();
            match yayatht_sys::socket::send(fd, chunk) {
                Ok(0) => return self.fail_dns_connection(),
                Ok(sent) => {
                    self.dns_write_buffer.drain(..sent);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return self.fail_dns_connection(),
            }
        }
        Ok(())
    }

    /// Reads the length-prefixed response stream. Returns false when the
    /// resolver closed or overflowed the connection.
    fn read_dns_stream(&mut self) -> Result<bool, Error> {
        let DnsConnection::Ready { socket } = &self.dns_connection else {
            return Ok(true);
        };
        let fd = socket.as_raw_fd();
        let mut chunk = [0u8; 4096];
        let mut alive = true;
        loop {
            match yayatht_sys::socket::recv(fd, &mut chunk) {
                Ok(0) => {
                    alive = false;
                    break;
                }
                Ok(length) => {
                    if self.dns_read_buffer.len() + length > DNS_READ_BUFFER_LIMIT {
                        alive = false;
                        break;
                    }
                    self.dns_read_buffer.extend_from_slice(&chunk[..length]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    alive = false;
                    break;
                }
            }
        }
        // Responses that arrived ahead of an EOF still count: answer them
        // before the connection teardown fails whatever remains.
        self.process_dns_frames()?;
        Ok(alive)
    }

    fn process_dns_frames(&mut self) -> Result<(), Error> {
        loop {
            if self.dns_read_buffer.len() < 2 {
                return Ok(());
            }
            let frame_len = usize::from(u16::from_be_bytes([
                self.dns_read_buffer[0],
                self.dns_read_buffer[1],
            ]));
            if self.dns_read_buffer.len() < 2 + frame_len {
                return Ok(());
            }
            let frame: Vec<u8> = self
                .dns_read_buffer
                .drain(..2 + frame_len)
                .skip(2)
                .collect();
            // The reply must fit one TAP frame; IPv6 overhead is assumed
            // so the bound holds for both families.
            let frame_limit = self.mtu_frame_capacity
                - self.vnet_len
                - ethernet::ETHERNET_HEADER_LEN
                - 40
                - udp::UDP_HEADER_LEN;
            if let Some(reply) = self.dns_engine.accept_response(&frame, frame_limit) {
                self.metrics.dns_responses += 1;
                if reply.truncated {
                    self.metrics.dns_truncated += 1;
                }
                self.dns_last_activity = Instant::now();
                self.queue_dns_reply(
                    reply.transaction.client,
                    reply.transaction.gateway,
                    &reply.payload,
                )?;
            }
        }
    }

    /// Tears down the resolver connection and answers every outstanding
    /// transaction SERVFAIL. The next query reconnects on demand.
    fn fail_dns_connection(&mut self) -> Result<(), Error> {
        self.dns_connection = DnsConnection::Idle;
        self.dns_write_buffer.clear();
        self.dns_read_buffer.clear();
        for (transaction, reply) in self.dns_engine.fail_all() {
            self.metrics.dns_failures += 1;
            self.queue_dns_reply(transaction.client, transaction.gateway, &reply)?;
        }
        Ok(())
    }

    fn update_dns_interest(&mut self) -> Result<(), Error> {
        let (fd, interest) = match &self.dns_connection {
            DnsConnection::Idle => return Ok(()),
            DnsConnection::Connecting {
                socket,
                connected,
                handshake,
            } => (
                socket.as_raw_fd(),
                socket_interest(
                    !connected,
                    handshake
                        .as_ref()
                        .is_some_and(|pending| !pending.output().is_empty()),
                    false,
                ),
            ),
            DnsConnection::Ready { socket } => (
                socket.as_raw_fd(),
                socket_interest(false, false, !self.dns_write_buffer.is_empty()),
            ),
        };
        self.epoll.modify(
            fd,
            interest,
            EpollToken::global(Resource::DnsUpstream).raw(),
        )?;
        Ok(())
    }

    /// Expires overdue transactions with SERVFAIL and closes the resolver
    /// connection after an idle period.
    fn handle_dns_timers(&mut self, now: Instant) -> Result<(), Error> {
        let expired = self.dns_engine.expire(now);
        for (transaction, reply) in expired {
            self.metrics.dns_failures += 1;
            self.queue_dns_reply(transaction.client, transaction.gateway, &reply)?;
        }
        if self.dns_engine.is_idle()
            && self.dns_write_buffer.is_empty()
            && !matches!(self.dns_connection, DnsConnection::Idle)
            && now.duration_since(self.dns_last_activity) >= DNS_IDLE_TIMEOUT
        {
            self.dns_connection = DnsConnection::Idle;
            self.dns_read_buffer.clear();
        }
        Ok(())
    }

    /// Builds and queues a gateway-sourced UDP frame carrying a DNS
    /// message back to its namespace client.
    fn queue_dns_reply(
        &mut self,
        client: SocketAddr,
        gateway: SocketAddr,
        payload: &[u8],
    ) -> Result<(), Error> {
        let vnet_len = self.vnet_len;
        let ip_header_len = if client.is_ipv4() { 20 } else { 40 };
        let ip_offset = vnet_len + ethernet::ETHERNET_HEADER_LEN;
        let udp_offset = ip_offset + ip_header_len;
        let frame_len = udp_offset + udp::UDP_HEADER_LEN + payload.len();
        // Pool exhaustion is a designed-in state under send-queue pressure,
        // not a fault. Every timer- and resolver-driven caller propagates
        // this Result to the run loop, so failing here would kill the whole
        // reactor. Degrade to a counted drop instead; the DNS client retries.
        let mut frame = match self.frame_pool.acquire() {
            Some((pool_index, buffer)) => PooledFrame {
                tier: FrameTier::Mtu,
                pool_index,
                buffer,
            },
            None => {
                self.note_frame_pool_exhaustion();
                self.metrics.dns_reply_drops += 1;
                return Ok(());
            }
        };
        if frame_len > frame.buffer.capacity() {
            self.release_frame(frame);
            return Err(Error::Invariant("DNS reply exceeds frame capacity"));
        }
        let result = (|| {
            let bytes = frame.buffer.writable();
            bytes[..vnet_len].fill(0);
            ethernet::write_header(
                &mut bytes[vnet_len..],
                self.config.target_mac,
                self.config.gateway_mac,
                if client.is_ipv4() {
                    EtherType::Ipv4
                } else {
                    EtherType::Ipv6
                },
            )?;
            bytes[udp_offset + udp::UDP_HEADER_LEN..frame_len].copy_from_slice(payload);
            udp::write_header(
                &mut bytes[udp_offset..frame_len],
                gateway.port(),
                client.port(),
                payload.len(),
            )?;
            match (gateway.ip(), client.ip()) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    ip::write_ipv4_header(
                        &mut bytes[ip_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                        ip::IPPROTO_UDP,
                        udp::UDP_HEADER_LEN + payload.len(),
                        0,
                    )?;
                    udp::set_ipv4_checksum(
                        &mut bytes[udp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )
                }
                (IpAddr::V6(source), IpAddr::V6(destination)) => {
                    ip::write_ipv6_header(
                        &mut bytes[ip_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                        ip::IPPROTO_UDP,
                        udp::UDP_HEADER_LEN + payload.len(),
                    )?;
                    udp::set_ipv6_checksum(
                        &mut bytes[udp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )
                }
                _ => Err(yayatht_packet::PacketError::ProtocolMismatch),
            }
        })();
        if let Err(error) = result {
            self.release_frame(frame);
            return Err(error.into());
        }
        frame.buffer.set_len(frame_len);
        self.queue_tap(None, frame, None)
    }

    fn route_target(&self, logical: SocketAddr) -> (FlowInterface, SocketAddr) {
        match &self.config.upstream {
            Upstream::Proxy { address, .. } => (FlowInterface::ProxyTunnel, *address),
            Upstream::Direct {
                host_loopback: false,
            } => (FlowInterface::HostSocket, logical),
            Upstream::Direct {
                host_loopback: true,
            } => (
                FlowInterface::HostSocket,
                match logical {
                    SocketAddr::V4(address) if Some(*address.ip()) == self.config.gateway_ipv4 => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
                    }
                    SocketAddr::V6(address) if Some(*address.ip()) == self.config.gateway_ipv6 => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), address.port())
                    }
                    _ => logical,
                },
            ),
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
            (
                entry
                    .construction
                    .active_sides()
                    .ok_or(Error::Invariant("inactive flow reached socket reader"))?
                    .namespace_key(),
                entry.socket.as_raw_fd(),
            )
        };
        let payload_offset = self.tcp_payload_offset(key, None, None);
        let offset = i32::try_from(offset)
            .map_err(|_| Error::Invariant("socket peek offset exceeds i32"))?;
        let mut frame = self.acquire_payload_frame(payload_offset + capacity)?;
        let capacity = capacity.min(frame.buffer.capacity().saturating_sub(payload_offset));
        let out = &mut frame.buffer.writable()[payload_offset..payload_offset + capacity];
        yayatht_sys::tcp_info::set_peek_offset(fd, offset)?;
        let result = yayatht_sys::socket::peek(fd, out);
        match result {
            Ok(0) => {
                self.release_frame(frame);
                if offset == 0 {
                    Ok(PeekedFrame::Eof)
                } else {
                    Ok(PeekedFrame::WouldBlock)
                }
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

    fn flow_frame_parameters(
        &self,
        id: FlowId,
        syn: bool,
    ) -> Result<(FlowKey, u16, u16, u8), Error> {
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
            entry
                .construction
                .active_sides()
                .expect("active construction checked")
                .namespace_key(),
            entry.flow.mss(),
            entry.flow.window_field(syn),
            entry.flow.local_window_shift(),
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
        let (key, mss, window, _) = match self.flow_frame_parameters(id, false) {
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
            window_scale: None,
            window,
            payload_len,
            // Payloads beyond one MSS become TSO super-frames the kernel
            // segments at the negotiated MSS.
            gso_size: Some(mss),
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
        let (key, mss, window, window_shift) = self.flow_frame_parameters(id, flags.syn)?;
        let window_scale = (flags.syn && window_shift > 0).then_some(window_shift);
        self.build_tcp_frame(
            key,
            plan,
            payload,
            flags,
            flags.syn.then_some(mss),
            window_scale,
            window,
        )
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
            None,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tcp_frame(
        &mut self,
        key: FlowKey,
        plan: SendPlan,
        payload: &[u8],
        flags: TcpFlags,
        mss: Option<u16>,
        window_scale: Option<u8>,
        window: u16,
    ) -> Result<PooledFrame, Error> {
        let mut frame = self.acquire_frame()?;
        let payload_offset = self.tcp_payload_offset(key, mss, window_scale);
        let frame_len = payload_offset + payload.len();
        if frame_len > frame.buffer.capacity() {
            self.release_frame(frame);
            return Err(Error::Invariant("TCP frame exceeds buffer capacity"));
        }
        frame.buffer.writable()[payload_offset..frame_len].copy_from_slice(payload);
        let spec = TcpFrameSpec {
            key,
            plan,
            flags,
            mss,
            window_scale,
            window,
            payload_len: payload.len(),
            gso_size: None,
        };
        if let Err(error) = self.finalize_tcp_frame(&mut frame, spec) {
            self.release_frame(frame);
            return Err(error);
        }
        Ok(frame)
    }

    fn acquire_frame(&mut self) -> Result<PooledFrame, Error> {
        match self.frame_pool.acquire() {
            Some((pool_index, buffer)) => Ok(PooledFrame {
                tier: FrameTier::Mtu,
                pool_index,
                buffer,
            }),
            None => {
                self.note_frame_pool_exhaustion();
                Err(Error::Invariant("TAP frame pool exhausted"))
            }
        }
    }

    /// Acquires a frame able to hold `required` bytes, drawing from the
    /// GSO tier beyond MTU-frame capacity. A dry GSO pool degrades to an
    /// MTU frame -- the send simply carries less payload -- and is
    /// counted, never failed.
    fn acquire_payload_frame(&mut self, required: usize) -> Result<PooledFrame, Error> {
        if required > self.mtu_frame_capacity {
            if let Some((pool_index, buffer)) = self.gso_pool.acquire() {
                return Ok(PooledFrame {
                    tier: FrameTier::Gso,
                    pool_index,
                    buffer,
                });
            }
            self.metrics.gso_pool_exhaustions += 1;
        }
        self.acquire_frame()
    }

    fn note_frame_pool_exhaustion(&mut self) {
        self.metrics.frame_pool_exhaustions += 1;
    }

    fn release_frame(&mut self, frame: PooledFrame) {
        match frame.tier {
            FrameTier::Mtu => self.frame_pool.release(frame.pool_index, frame.buffer),
            FrameTier::Gso => self.gso_pool.release(frame.pool_index, frame.buffer),
        }
    }

    /// Offset of the TCP payload within a TAP frame buffer: the
    /// `virtio_net_hdr` prefix (when negotiated) plus Ethernet, IP and TCP
    /// headers.
    fn tcp_payload_offset(
        &self,
        key: FlowKey,
        mss: Option<u16>,
        window_scale: Option<u8>,
    ) -> usize {
        let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
        let tcp_header_len = tcp::TCP_MIN_HEADER_LEN
            + if mss.is_some() { 4 } else { 0 }
            + if window_scale.is_some() { 4 } else { 0 };
        self.vnet_len + ethernet::ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len
    }

    fn finalize_tcp_frame(
        &mut self,
        frame: &mut PooledFrame,
        spec: TcpFrameSpec,
    ) -> Result<(), Error> {
        let TcpFrameSpec {
            key,
            plan,
            flags,
            mss,
            window_scale,
            window,
            payload_len,
            gso_size,
        } = spec;
        let ip_header_len = if key.target.is_ipv4() { 20 } else { 40 };
        let payload_offset = self.tcp_payload_offset(key, mss, window_scale);
        let frame_len = payload_offset + payload_len;
        let bytes = frame.buffer.writable();
        bytes[..self.vnet_len].fill(0);
        ethernet::write_header(
            &mut bytes[self.vnet_len..],
            self.config.target_mac,
            self.config.gateway_mac,
            if key.target.is_ipv4() {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
        )?;
        let ip_offset = self.vnet_len + ethernet::ETHERNET_HEADER_LEN;
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
                window_scale,
            },
        )?;
        let offload = self.vnet_len > 0;
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
                if offload {
                    tcp::set_ipv4_partial_checksum(
                        &mut bytes[tcp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )?;
                } else {
                    tcp::set_ipv4_checksum(
                        &mut bytes[tcp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )?;
                }
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                ip::write_ipv6_header(
                    &mut bytes[ip_offset..frame_len],
                    source.octets(),
                    destination.octets(),
                    ip::IPPROTO_TCP,
                    written + payload_len,
                )?;
                if offload {
                    tcp::set_ipv6_partial_checksum(
                        &mut bytes[tcp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )?;
                } else {
                    tcp::set_ipv6_checksum(
                        &mut bytes[tcp_offset..frame_len],
                        source.octets(),
                        destination.octets(),
                    )?;
                }
            }
            _ => return Err(Error::Invariant("mixed address families in flow")),
        }
        if offload {
            // The kernel completes the transport checksum from csum_start
            // over the seeded pseudo-header sum; offsets are relative to
            // the frame body after the vnet header. Payloads beyond one
            // MSS additionally carry GSO state and are segmented by the
            // kernel at gso_size.
            let gso_size = gso_size.filter(|&gso_size| payload_len > usize::from(gso_size));
            if gso_size.is_some() {
                self.metrics.gso_frames_tx += 1;
            }
            vnet::VnetHeader {
                flags: vnet::FLAG_NEEDS_CSUM,
                gso_type: match gso_size {
                    None => vnet::GSO_NONE,
                    Some(_) if key.target.is_ipv4() => vnet::GSO_TCPV4,
                    Some(_) => vnet::GSO_TCPV6,
                },
                hdr_len: (payload_offset - self.vnet_len) as u16,
                gso_size: gso_size.unwrap_or(0),
                csum_start: (ethernet::ETHERNET_HEADER_LEN + ip_header_len) as u16,
                csum_offset: 16,
            }
            .write(&mut bytes[..self.vnet_len])?;
        }
        frame.buffer.set_len(frame_len);
        Ok(())
    }

    fn send_reset_for_flow(&mut self, id: FlowId) -> Result<(), Error> {
        let entry = self.flows.get(id).expect("flow exists");
        let key = entry
            .construction
            .active_sides()
            .ok_or(Error::Invariant("inactive flow reached reset builder"))?
            .namespace_key();
        let frame = self.build_reset(key, entry.flow.namespace_ack())?;
        self.metrics.tcp_resets += 1;
        self.queue_tap(None, frame, None)
    }

    fn queue_tap(
        &mut self,
        flow: Option<FlowId>,
        frame: PooledFrame,
        plan: Option<SendPlan>,
    ) -> Result<(), Error> {
        let reserved_retained = plan.map_or(0, |plan| plan.length);
        if !self.reserve_retained_bytes(reserved_retained) {
            self.release_frame(frame);
            return Err(Error::Invariant(
                "retained TCP reservation exceeded hard limit",
            ));
        }
        let injected_drop = if self.tap_queue.is_empty() {
            plan.is_some_and(|plan| {
                if plan.syn && self.test_drop_tcp_syn_ack > 0 {
                    self.test_drop_tcp_syn_ack -= 1;
                    true
                } else if plan.fin && self.test_drop_tcp_fin > 0 {
                    self.test_drop_tcp_fin -= 1;
                    true
                } else if plan.length > 0 && self.test_drop_tcp_data > 0 {
                    self.test_drop_tcp_data -= 1;
                    true
                } else if !plan.syn && !plan.fin && plan.length == 0 && self.test_drop_tcp_ack > 0 {
                    self.test_drop_tcp_ack -= 1;
                    true
                } else {
                    false
                }
            })
        } else {
            false
        };
        if injected_drop {
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
                    self.release_retained_bytes(reserved_retained);
                    self.release_frame(frame);
                    return Err(Error::Invariant("short TAP frame write"));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    self.release_retained_bytes(reserved_retained);
                    self.release_frame(frame);
                    return Err(error.into());
                }
            }
        }
        self.tap_queue.push_back(QueuedFrame {
            flow,
            frame,
            plan,
            reserved_retained,
        });
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
                    self.release_retained_bytes(frame.reserved_retained);
                    self.release_frame(frame.frame);
                    return Err(Error::Invariant("short TAP frame write"));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.tap_queue.push_front(frame);
                    break;
                }
                Err(error) => {
                    self.release_retained_bytes(frame.reserved_retained);
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

    fn reserve_retained_bytes(&mut self, length: usize) -> bool {
        if length
            > self
                .config
                .max_retained_tcp_bytes
                .saturating_sub(self.retained_socket_bytes)
        {
            self.metrics.retained_limit_hits += 1;
            return false;
        }
        self.retained_socket_bytes += length;
        self.metrics.retained_tcp_bytes = self.retained_socket_bytes as u64;
        self.metrics.peak_retained_tcp_bytes = self
            .metrics
            .peak_retained_tcp_bytes
            .max(self.metrics.retained_tcp_bytes);
        true
    }

    fn release_retained_bytes(&mut self, length: usize) {
        self.retained_socket_bytes = self.retained_socket_bytes.saturating_sub(length);
        self.metrics.retained_tcp_bytes = self.retained_socket_bytes as u64;
    }

    fn close_flow(&mut self, id: FlowId) -> Result<(), Error> {
        let Some(entry) = self.flows.get(id) else {
            return Ok(());
        };
        let fd = entry.socket.as_raw_fd();
        let pending_socket_bytes = entry.pending_socket.len();
        let retained_socket_bytes = entry
            .sent_segments
            .iter()
            .map(|segment| segment.payload_len)
            .sum::<usize>();
        let socket_receive_buffer_bytes = entry.socket_receive_buffer_bytes;
        let socket_send_buffer_bytes = entry.socket_send_buffer_bytes;
        let had_zero_window = entry.zero_window_probe.is_some();
        let key = entry
            .construction
            .active_sides()
            .ok_or(Error::Invariant("inactive flow reached cleanup"))?
            .namespace_key();
        self.epoll.delete(fd)?;
        self.by_key.remove(&key);
        let mut retained = VecDeque::with_capacity(self.tap_queue.len());
        while let Some(frame) = self.tap_queue.pop_front() {
            if frame.flow == Some(id) {
                self.release_retained_bytes(frame.reserved_retained);
                self.release_frame(frame.frame);
            } else {
                retained.push_back(frame);
            }
        }
        self.tap_queue = retained;
        self.pending_socket_bytes = self
            .pending_socket_bytes
            .saturating_sub(pending_socket_bytes);
        self.metrics.pending_tcp_bytes = self.pending_socket_bytes as u64;
        self.update_pending_pressure_state();
        self.release_retained_bytes(retained_socket_bytes);
        self.metrics.active_tcp_flows = self.metrics.active_tcp_flows.saturating_sub(1);
        self.metrics.socket_receive_buffer_bytes = self
            .metrics
            .socket_receive_buffer_bytes
            .saturating_sub(socket_receive_buffer_bytes as u64);
        self.metrics.socket_send_buffer_bytes = self
            .metrics
            .socket_send_buffer_bytes
            .saturating_sub(socket_send_buffer_bytes as u64);
        if had_zero_window {
            self.metrics.zero_window_flows = self.metrics.zero_window_flows.saturating_sub(1);
        }
        self.update_tap_interest()?;
        self.flows.get_mut(id).expect("flow exists").flow.close();
        self.flows.defer_remove(id);
        Ok(())
    }

    fn cleanup_closed(&mut self) -> Result<(), Error> {
        let removed = self.flows.flush_deferred();
        self.metrics.tcp_closed += removed.len() as u64;
        Ok(())
    }
}

fn test_drop_tcp_data_count() -> usize {
    test_count(TEST_DROP_TCP_DATA_ENV)
}

fn test_count(name: &str) -> usize {
    test_value(name).unwrap_or(0)
}

fn test_value<T: std::str::FromStr>(name: &str) -> Option<T> {
    #[cfg(debug_assertions)]
    {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
        None
    }
}

fn pending_pressure_state(current: bool, bytes: usize, limit: usize) -> bool {
    let high = limit.saturating_mul(7) / 8;
    let low = limit.saturating_mul(3) / 4;
    if current { bytes > low } else { bytes >= high }
}

/// Level-triggered `EPOLLOUT` on an idle socket wakes the reactor on every
/// `epoll_wait`, so writable interest is armed only while a writable event
/// can make progress: a pending nonblocking connect, unflushed proxy
/// handshake output, or queued payload waiting for send-buffer space.
/// Upstream ACK progress never arms writable interest: a TCP socket is
/// writable almost permanently, so polling it busy-loops the reactor.
/// ACK progress arrives through TX ACK timestamp error-queue events, with
/// the periodic timer watchdog bounding the delay when a notification is
/// lost.
const fn socket_interest(
    connect_pending: bool,
    handshake_output_pending: bool,
    queued_payload: bool,
) -> u32 {
    let base = yayatht_sys::reactor::READABLE
        | yayatht_sys::reactor::ERROR
        | yayatht_sys::reactor::READ_HANGUP;
    if connect_pending || handshake_output_pending || queued_payload {
        base | yayatht_sys::reactor::WRITABLE
    } else {
        base
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

    #[test]
    fn writable_interest_is_armed_only_while_progress_is_possible() {
        let base = yayatht_sys::reactor::READABLE
            | yayatht_sys::reactor::ERROR
            | yayatht_sys::reactor::READ_HANGUP;
        let writable = base | yayatht_sys::reactor::WRITABLE;
        // Idle established flow: epoll_wait must be able to block. Flows
        // with unacknowledged upstream bytes stay unarmed too; the ACK
        // watchdog covers them without writable busy-polling.
        assert_eq!(socket_interest(false, false, false), base);
        assert_eq!(socket_interest(true, false, false), writable);
        assert_eq!(socket_interest(false, true, false), writable);
        assert_eq!(socket_interest(false, false, true), writable);
    }

    #[test]
    fn pending_pressure_uses_high_and_low_watermarks() {
        let limit = 1024;
        assert!(!pending_pressure_state(false, 895, limit));
        assert!(pending_pressure_state(false, 896, limit));
        assert!(pending_pressure_state(true, 769, limit));
        assert!(!pending_pressure_state(true, 768, limit));
    }

    #[test]
    fn retransmission_backoff_stops_at_the_retry_limit() {
        let started = Instant::now();
        let mut segment = segment(100, 10, false, false);
        for retry in 1..=MAX_RETRIES {
            segment.record_timeout_retransmit(started);
            assert_eq!(segment.retries, retry);
        }
        assert!(segment.retries_exhausted());
        assert_eq!(segment.retransmit_timeout, Duration::from_secs(8));
    }

    fn test_reactor() -> Reactor {
        use std::net::UdpSocket;
        // Any epoll-addable fds satisfy Reactor::new; the pool-exhaustion
        // path never touches them.
        let tap = OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap());
        let control = OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap());
        let config = Config {
            target_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            gateway_mac: MacAddress([2, 0, 0, 0, 0, 2]),
            target_ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
            gateway_ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            target_ipv6: None,
            gateway_ipv6: None,
            tap_mtu: 1500,
            tap_offload: false,
            upstream: Upstream::Direct {
                host_loopback: false,
            },
            dns_proxy_tcp: true,
            dns_upstream: Some(SocketAddr::from(([127, 0, 0, 1], 53))),
            max_tcp_flows: 8,
            max_pending_tcp_bytes: 65536,
            max_retained_tcp_bytes: 65536,
            tcp_receive_buffer_bytes: 65536,
            tcp_send_buffer_bytes: 65536,
        };
        Reactor::new(config, tap, control).unwrap()
    }

    #[test]
    fn dns_reply_degrades_to_a_counted_drop_when_the_frame_pool_is_dry() {
        let mut reactor = test_reactor();
        // Drain every frame so the reply cannot acquire one. Leak the
        // handles; the pool must observe zero availability.
        let mut held = Vec::new();
        while let Some(frame) = reactor.frame_pool.acquire() {
            held.push(frame);
        }
        assert_eq!(reactor.frame_pool.available(), 0);

        let client = SocketAddr::from(([10, 0, 0, 2], 40000));
        let gateway = SocketAddr::from(([10, 0, 0, 1], 53));
        let result = reactor.queue_dns_reply(client, gateway, &[0u8; 32]);

        // The timer and resolver callers propagate this Result with `?`, so
        // a dry pool must not surface an error that would kill the reactor.
        assert!(result.is_ok());
        assert_eq!(reactor.metrics.dns_reply_drops, 1);
        assert_eq!(reactor.metrics.frame_pool_exhaustions, 1);
        assert_eq!(reactor.metrics.tap_tx_packets, 0);
    }
}
