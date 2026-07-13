use crate::sequence;
use std::net::{IpAddr, SocketAddr};

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
    Reset,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendPlan {
    pub sequence: u32,
    pub acknowledgment: u32,
    pub length: usize,
    pub fin: bool,
}

#[derive(Debug)]
pub struct Flow {
    key: FlowKey,
    state: State,
    namespace_initial: u32,
    namespace_next: u32,
    namespace_acked: u32,
    local_initial: u32,
    local_unacked: u32,
    local_next: u32,
    peer_window: u16,
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
    pub fn new(key: FlowKey, namespace_initial: u32, local_initial: u32, mss: u16) -> Self {
        Self {
            key,
            state: State::Connecting,
            namespace_initial,
            namespace_next: namespace_initial.wrapping_add(1),
            namespace_acked: namespace_initial.wrapping_add(1),
            local_initial,
            local_unacked: local_initial,
            local_next: local_initial,
            peer_window: u16::MAX,
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
    pub const fn key(&self) -> FlowKey {
        self.key
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
    pub const fn unacked_to_namespace(&self) -> u32 {
        sequence::distance(self.local_unacked, self.local_next)
    }

    #[must_use]
    pub const fn available_namespace_window(&self) -> usize {
        let used = self.unacked_to_namespace();
        self.peer_window.saturating_sub(used as u16) as usize
    }

    pub fn socket_connected(&mut self, bytes_acked: u64) -> SendPlan {
        self.upstream_ack_baseline = bytes_acked;
        self.state = State::SynReceived;
        let plan = SendPlan {
            sequence: self.local_initial,
            acknowledgment: self.namespace_next,
            length: 0,
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

    #[must_use]
    pub const fn family(&self) -> libc_family::Family {
        match self.key.target.ip() {
            IpAddr::V4(_) => libc_family::Family::Inet,
            IpAddr::V6(_) => libc_family::Family::Inet6,
        }
    }
}

pub mod libc_family {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Family {
        Inet,
        Inet6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> Flow {
        Flow::new(
            FlowKey {
                namespace: "192.0.2.2:40000".parse().unwrap(),
                target: "192.0.2.1:7".parse().unwrap(),
            },
            u32::MAX - 4,
            100,
            1460,
        )
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
}
