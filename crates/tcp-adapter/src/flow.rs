use crate::sequence;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowInterface {
    NamespaceTap,
    HostSocket,
    ProxyTunnel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowSide {
    pub interface: FlowInterface,
    pub local_endpoint: SocketAddr,
    pub logical_peer: SocketAddr,
    pub transport_peer: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowSides {
    pub initiating: FlowSide,
    pub target: FlowSide,
}

impl FlowSides {
    #[must_use]
    pub const fn namespace_key(self) -> FlowKey {
        FlowKey {
            namespace: self.initiating.logical_peer,
            target: self.initiating.local_endpoint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowType {
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructionState {
    New,
    Initiated,
    Targeted,
    Typed,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowConstruction {
    state: ConstructionState,
    initiating: Option<FlowSide>,
    target: Option<FlowSide>,
    flow_type: Option<FlowType>,
}

impl Default for FlowConstruction {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowConstruction {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConstructionState::New,
            initiating: None,
            target: None,
            flow_type: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> ConstructionState {
        self.state
    }

    pub fn set_initiating(&mut self, side: FlowSide) -> Result<(), ConstructionState> {
        if self.state != ConstructionState::New {
            return Err(self.state);
        }
        self.initiating = Some(side);
        self.state = ConstructionState::Initiated;
        Ok(())
    }

    pub fn set_target(&mut self, side: FlowSide) -> Result<(), ConstructionState> {
        if self.state != ConstructionState::Initiated {
            return Err(self.state);
        }
        self.target = Some(side);
        self.state = ConstructionState::Targeted;
        Ok(())
    }

    pub fn set_type(&mut self, flow_type: FlowType) -> Result<(), ConstructionState> {
        if self.state != ConstructionState::Targeted {
            return Err(self.state);
        }
        self.flow_type = Some(flow_type);
        self.state = ConstructionState::Typed;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<FlowSides, ConstructionState> {
        if self.state != ConstructionState::Typed || self.flow_type != Some(FlowType::Tcp) {
            return Err(self.state);
        }
        let sides = FlowSides {
            initiating: self.initiating.expect("initiating side set before typed"),
            target: self.target.expect("target side set before typed"),
        };
        self.state = ConstructionState::Active;
        Ok(sides)
    }

    #[must_use]
    pub fn active_sides(&self) -> Option<FlowSides> {
        (self.state == ConstructionState::Active).then(|| FlowSides {
            initiating: self.initiating.expect("active flow has initiating side"),
            target: self.target.expect("active flow has target side"),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub namespace: SocketAddr,
    pub target: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Connecting,
    SynReceived,
    Established,
    NamespaceFinReceived,
    SocketFinReceived,
    Closing,
    TimeWait,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    InOrder { payload_len: usize, fin: bool },
    Duplicate,
    OutOfOrder,
    OutsideWindow,
    Reset,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendPlan {
    pub sequence: u32,
    pub acknowledgment: u32,
    pub length: usize,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Debug)]
pub struct Flow {
    state: State,
    namespace_initial: u32,
    namespace_next: u32,
    namespace_acked: u32,
    local_initial: u32,
    local_unacked: u32,
    local_next: u32,
    peer_window: u16,
    advertised_window: u16,
    mss: u16,
    upstream_ack_baseline: u64,
    upstream_submitted: u64,
    upstream_acked: u64,
    namespace_fin: bool,
    socket_fin: bool,
    local_fin_sequence: Option<u32>,
}

impl Flow {
    #[must_use]
    pub fn new(namespace_initial: u32, local_initial: u32, mss: u16) -> Self {
        Self {
            state: State::Connecting,
            namespace_initial,
            namespace_next: namespace_initial.wrapping_add(1),
            namespace_acked: namespace_initial.wrapping_add(1),
            local_initial,
            local_unacked: local_initial,
            local_next: local_initial,
            peer_window: u16::MAX,
            advertised_window: u16::MAX,
            mss,
            upstream_ack_baseline: 0,
            upstream_submitted: 0,
            upstream_acked: 0,
            namespace_fin: false,
            socket_fin: false,
            local_fin_sequence: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn mss(&self) -> u16 {
        self.mss
    }

    #[must_use]
    pub const fn namespace_ack(&self) -> u32 {
        self.namespace_acked
    }

    #[must_use]
    pub const fn local_unacked(&self) -> u32 {
        self.local_unacked
    }

    #[must_use]
    pub const fn local_next(&self) -> u32 {
        self.local_next
    }

    #[must_use]
    pub const fn peer_window(&self) -> u16 {
        self.peer_window
    }

    #[must_use]
    pub const fn advertised_window(&self) -> u16 {
        self.advertised_window
    }

    pub fn set_advertised_window(&mut self, window: u16) -> bool {
        if self.advertised_window == window {
            return false;
        }
        self.advertised_window = window;
        true
    }

    #[must_use]
    pub const fn unacked_to_namespace(&self) -> u32 {
        sequence::distance(self.local_unacked, self.local_next)
    }

    #[must_use]
    pub const fn available_namespace_window(&self) -> usize {
        let used = self.unacked_to_namespace() as usize;
        (self.peer_window as usize).saturating_sub(used)
    }

    pub fn socket_connected(&mut self, bytes_acked: u64) -> SendPlan {
        self.upstream_ack_baseline = bytes_acked;
        self.state = State::SynReceived;
        let plan = SendPlan {
            sequence: self.local_initial,
            acknowledgment: self.namespace_next,
            length: 0,
            syn: true,
            fin: false,
        };
        self.local_next = self.local_initial.wrapping_add(1);
        plan
    }

    pub fn receive(
        &mut self,
        sequence_number: u32,
        acknowledgment: Option<u32>,
        window: u16,
        payload_len: usize,
        fin: bool,
        rst: bool,
    ) -> ReceiveDisposition {
        if rst {
            self.state = State::Closed;
            return ReceiveDisposition::Reset;
        }
        self.peer_window = window;
        if let Some(ack) = acknowledgment {
            self.acknowledge_local(ack);
            if self.state == State::SynReceived && ack == self.local_initial.wrapping_add(1) {
                self.state = State::Established;
            }
        }
        if sequence_number != self.namespace_next {
            return if sequence::before(sequence_number, self.namespace_next) {
                ReceiveDisposition::Duplicate
            } else {
                ReceiveDisposition::OutOfOrder
            };
        }
        if payload_len > usize::from(self.advertised_window) {
            return ReceiveDisposition::OutsideWindow;
        }
        if payload_len == 0 && !fin {
            return ReceiveDisposition::InOrder {
                payload_len: 0,
                fin: false,
            };
        }
        let Ok(length) = u32::try_from(payload_len) else {
            return ReceiveDisposition::Invalid;
        };
        self.namespace_next = self.namespace_next.wrapping_add(length);
        self.advertised_window = self.advertised_window.saturating_sub(length as u16);
        if fin {
            self.namespace_next = self.namespace_next.wrapping_add(1);
            self.namespace_fin = true;
            if self.upstream_acked == self.upstream_submitted {
                self.namespace_acked = self.namespace_next;
            }
            self.state = if self.socket_fin && self.local_unacked == self.local_next {
                State::TimeWait
            } else if self.socket_fin {
                State::Closing
            } else {
                State::NamespaceFinReceived
            };
        }
        ReceiveDisposition::InOrder { payload_len, fin }
    }

    pub fn record_upstream_submitted(&mut self, length: usize) {
        self.upstream_submitted = self.upstream_submitted.saturating_add(length as u64);
    }

    #[must_use]
    pub const fn upstream_submitted(&self) -> u64 {
        self.upstream_submitted
    }

    pub fn record_upstream_ack(&mut self, bytes_acked: u64) -> bool {
        let acknowledged = bytes_acked
            .saturating_sub(self.upstream_ack_baseline)
            .min(self.upstream_submitted);
        if acknowledged <= self.upstream_acked {
            return false;
        }
        self.upstream_acked = acknowledged;
        self.namespace_acked = self
            .namespace_initial
            .wrapping_add(1)
            .wrapping_add(acknowledged as u32);
        if self.namespace_fin && acknowledged == self.upstream_submitted {
            self.namespace_acked = self.namespace_acked.wrapping_add(1);
        }
        true
    }

    pub fn plan_send(&self, length: usize, fin: bool) -> Option<SendPlan> {
        if length > self.available_namespace_window() || length > usize::from(self.mss) {
            return None;
        }
        Some(SendPlan {
            sequence: self.local_next,
            acknowledgment: self.namespace_acked,
            length,
            syn: false,
            fin,
        })
    }

    pub fn commit_send(&mut self, plan: SendPlan) {
        self.local_next = self.local_next.wrapping_add(plan.length as u32);
        if plan.fin {
            self.local_fin_sequence = Some(self.local_next);
            self.local_next = self.local_next.wrapping_add(1);
            self.socket_fin = true;
            self.state = if self.namespace_fin {
                State::Closing
            } else {
                State::SocketFinReceived
            };
        }
    }

    #[must_use]
    pub fn newly_acked_payload(&self, previous_ack: u32) -> usize {
        let payload_start = self.local_initial.wrapping_add(1);
        let payload_end = self.local_fin_sequence.unwrap_or(self.local_next);
        let start = if sequence::before(previous_ack, payload_start) {
            payload_start
        } else {
            previous_ack
        };
        let end = if sequence::after(self.local_unacked, payload_end) {
            payload_end
        } else {
            self.local_unacked
        };
        if sequence::after(end, start) {
            sequence::distance(start, end) as usize
        } else {
            0
        }
    }

    pub fn mark_socket_fin(&mut self) {
        self.socket_fin = true;
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    fn acknowledge_local(&mut self, acknowledgment: u32) {
        if sequence::after(acknowledgment, self.local_unacked)
            && sequence::before_or_equal(acknowledgment, self.local_next)
        {
            self.local_unacked = acknowledgment;
        }
        if let Some(fin_sequence) = self.local_fin_sequence
            && sequence::after(acknowledgment, fin_sequence)
            && self.namespace_fin
        {
            self.state = State::TimeWait;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> Flow {
        Flow::new(u32::MAX - 4, 100, 1460)
    }

    #[test]
    fn handshake_and_wrapped_payload_ack() {
        let mut flow = flow();
        let syn_ack = flow.socket_connected(10);
        assert_eq!(syn_ack.sequence, 100);
        let disposition = flow.receive(u32::MAX - 3, Some(101), 65535, 8, false, false);
        assert_eq!(
            disposition,
            ReceiveDisposition::InOrder {
                payload_len: 8,
                fin: false
            }
        );
        flow.record_upstream_submitted(8);
        assert!(flow.record_upstream_ack(18));
        assert_eq!(flow.namespace_ack(), 4);
    }

    #[test]
    fn duplicate_is_not_submitted_twice() {
        let mut flow = flow();
        flow.socket_connected(0);
        flow.receive(u32::MAX - 3, Some(101), 65535, 4, false, false);
        assert_eq!(
            flow.receive(u32::MAX - 3, Some(101), 65535, 4, false, false),
            ReceiveDisposition::Duplicate
        );
    }

    #[test]
    fn completed_half_closes_enter_time_wait() {
        let mut flow = flow();
        flow.socket_connected(0);
        flow.receive(u32::MAX - 3, Some(101), 65535, 0, false, false);
        let fin = flow.plan_send(0, true).unwrap();
        flow.commit_send(fin);
        flow.receive(u32::MAX - 3, Some(flow.local_next()), 65535, 0, true, false);
        assert_eq!(flow.state(), State::TimeWait);
        assert_eq!(flow.namespace_ack(), u32::MAX - 2);
    }

    #[test]
    fn window_allows_multiple_inflight_segments() {
        let mut flow = flow();
        flow.socket_connected(0);
        flow.receive(u32::MAX - 3, Some(101), 12, 0, false, false);

        let first = flow.plan_send(4, false).unwrap();
        flow.commit_send(first);
        let second = flow.plan_send(4, false).unwrap();
        flow.commit_send(second);

        assert_eq!(flow.unacked_to_namespace(), 8);
        assert_eq!(flow.available_namespace_window(), 4);
        assert!(flow.plan_send(5, false).is_none());
        assert!(flow.plan_send(4, false).is_some());
    }

    #[test]
    fn receive_window_rejects_unreserved_payload() {
        let mut flow = flow();
        flow.socket_connected(0);
        flow.set_advertised_window(4);
        assert_eq!(
            flow.receive(u32::MAX - 3, Some(101), 65535, 5, false, false),
            ReceiveDisposition::OutsideWindow
        );
        assert_eq!(flow.namespace_ack(), u32::MAX - 3);
        assert_eq!(flow.advertised_window(), 4);

        assert_eq!(
            flow.receive(u32::MAX - 3, Some(101), 65535, 4, false, false),
            ReceiveDisposition::InOrder {
                payload_len: 4,
                fin: false
            }
        );
        assert_eq!(flow.advertised_window(), 0);
    }

    #[test]
    fn flow_construction_separates_logical_and_transport_targets() {
        let namespace = FlowSide {
            interface: FlowInterface::NamespaceTap,
            local_endpoint: "192.0.2.1:443".parse().unwrap(),
            logical_peer: "192.0.2.2:40000".parse().unwrap(),
            transport_peer: "192.0.2.2:40000".parse().unwrap(),
        };
        let target = FlowSide {
            interface: FlowInterface::ProxyTunnel,
            local_endpoint: "127.0.0.1:50000".parse().unwrap(),
            logical_peer: "198.51.100.7:443".parse().unwrap(),
            transport_peer: "127.0.0.1:7890".parse().unwrap(),
        };
        let mut construction = FlowConstruction::new();
        construction.set_initiating(namespace).unwrap();
        construction.set_target(target).unwrap();
        construction.set_type(FlowType::Tcp).unwrap();
        assert_eq!(construction.state(), ConstructionState::Typed);

        let sides = construction.activate().unwrap();
        assert_eq!(construction.state(), ConstructionState::Active);
        assert_eq!(sides.target.local_endpoint, target.local_endpoint);
        assert_eq!(sides.target.logical_peer, target.logical_peer);
        assert_eq!(sides.target.transport_peer, target.transport_peer);
        assert_ne!(sides.target.logical_peer, sides.target.transport_peer);
        assert_eq!(
            sides.namespace_key(),
            FlowKey {
                namespace: namespace.logical_peer,
                target: namespace.local_endpoint,
            }
        );
    }

    #[test]
    fn flow_construction_rejects_out_of_order_transitions() {
        let mut construction = FlowConstruction::new();
        assert_eq!(
            construction.set_type(FlowType::Tcp),
            Err(ConstructionState::New)
        );
        assert!(construction.active_sides().is_none());
    }
}
