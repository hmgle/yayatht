use crate::flow_table::{FlowId, FlowTable};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const DNS_TIMEOUT: Duration = Duration::from_secs(15);
pub const ONE_SHOT_TIMEOUT: Duration = Duration::from_secs(30);
pub const STREAM_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AssociationKey {
    pub source: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: SocketAddr,
    pub target: SocketAddr,
}

impl FlowKey {
    #[must_use]
    pub const fn association(self) -> AssociationKey {
        AssociationKey {
            source: self.source,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutClass {
    Dns,
    OneShot,
    Stream,
}

impl TimeoutClass {
    #[must_use]
    pub const fn duration(self) -> Duration {
        match self {
            Self::Dns => DNS_TIMEOUT,
            Self::OneShot => ONE_SHOT_TIMEOUT,
            Self::Stream => STREAM_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Flow {
    pub key: FlowKey,
    last_activity: Instant,
    outbound_datagrams: u8,
    inbound_datagrams: u8,
}

impl Flow {
    #[must_use]
    pub fn timeout_class(self) -> TimeoutClass {
        if self.key.target.port() == 53 {
            TimeoutClass::Dns
        } else if self.outbound_datagrams > 1 && self.inbound_datagrams > 1 {
            TimeoutClass::Stream
        } else {
            TimeoutClass::OneShot
        }
    }

    #[must_use]
    pub fn expires_at(self) -> Instant {
        self.last_activity + self.timeout_class().duration()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accept {
    pub id: FlowId,
    pub created: bool,
    pub association_created: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptError {
    FamilyMismatch,
    FlowLimit,
    AssociationLimit,
}

#[derive(Clone, Copy, Debug)]
struct Association {
    flow_count: usize,
}

pub struct Engine {
    flows: FlowTable<Flow>,
    by_key: HashMap<FlowKey, FlowId>,
    associations: HashMap<AssociationKey, Association>,
    max_flows: usize,
    max_associations: usize,
}

impl Engine {
    #[must_use]
    pub fn new(max_flows: usize, max_associations: usize) -> Self {
        Self {
            flows: FlowTable::with_capacity(max_flows),
            by_key: HashMap::with_capacity(max_flows),
            associations: HashMap::with_capacity(max_associations),
            max_flows,
            max_associations,
        }
    }

    pub fn accept(&mut self, key: FlowKey, now: Instant) -> Result<Accept, AcceptError> {
        if key.source.is_ipv4() != key.target.is_ipv4() {
            return Err(AcceptError::FamilyMismatch);
        }
        if let Some(&id) = self.by_key.get(&key) {
            self.record_outbound(id, now);
            return Ok(Accept {
                id,
                created: false,
                association_created: false,
            });
        }
        if self.by_key.len() >= self.max_flows {
            return Err(AcceptError::FlowLimit);
        }
        let association_key = key.association();
        let association_created = !self.associations.contains_key(&association_key);
        if association_created && self.associations.len() >= self.max_associations {
            return Err(AcceptError::AssociationLimit);
        }
        if association_created {
            self.associations
                .insert(association_key, Association { flow_count: 0 });
        }
        let flow = Flow {
            key,
            last_activity: now,
            outbound_datagrams: 1,
            inbound_datagrams: 0,
        };
        let id = match self.flows.insert(flow) {
            Ok(id) => id,
            Err(_) => {
                if association_created {
                    self.associations.remove(&association_key);
                }
                return Err(AcceptError::FlowLimit);
            }
        };
        self.by_key.insert(key, id);
        self.associations
            .get_mut(&association_key)
            .expect("association was inserted")
            .flow_count += 1;
        Ok(Accept {
            id,
            created: true,
            association_created,
        })
    }

    pub fn record_outbound(&mut self, id: FlowId, now: Instant) {
        if let Some(flow) = self.flows.get_mut(id) {
            flow.last_activity = now;
            flow.outbound_datagrams = flow.outbound_datagrams.saturating_add(1);
        }
    }

    pub fn record_inbound(&mut self, id: FlowId, now: Instant) {
        if let Some(flow) = self.flows.get_mut(id) {
            flow.last_activity = now;
            flow.inbound_datagrams = flow.inbound_datagrams.saturating_add(1);
        }
    }

    #[must_use]
    pub fn flow(&self, id: FlowId) -> Option<Flow> {
        self.flows.get(id).copied()
    }

    #[must_use]
    pub fn active_ids(&self) -> Vec<FlowId> {
        self.flows.active_ids()
    }

    #[must_use]
    pub fn active_flows(&self) -> usize {
        self.by_key.len()
    }

    #[must_use]
    pub fn active_associations(&self) -> usize {
        self.associations.len()
    }

    pub fn remove(&mut self, id: FlowId) -> bool {
        let Some(flow) = self.flows.get(id).copied() else {
            return false;
        };
        self.by_key.remove(&flow.key);
        let association_key = flow.key.association();
        let remove_association =
            if let Some(association) = self.associations.get_mut(&association_key) {
                association.flow_count = association.flow_count.saturating_sub(1);
                association.flow_count == 0
            } else {
                false
            };
        if remove_association {
            self.associations.remove(&association_key);
        }
        self.flows.defer_remove(id);
        let removed = self.flows.flush_deferred();
        debug_assert_eq!(removed.len(), 1);
        true
    }

    pub fn expire(&mut self, now: Instant) -> Vec<FlowId> {
        let expired = self
            .flows
            .active_ids()
            .into_iter()
            .filter(|&id| {
                self.flows
                    .get(id)
                    .is_some_and(|flow| flow.expires_at() <= now)
            })
            .collect::<Vec<_>>();
        for &id in &expired {
            let removed = self.remove(id);
            debug_assert!(removed);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(source_port: u16, target: &str) -> FlowKey {
        FlowKey {
            source: format!("192.0.2.2:{source_port}").parse().unwrap(),
            target: target.parse().unwrap(),
        }
    }

    #[test]
    fn one_association_serves_multiple_targets() {
        let now = Instant::now();
        let mut engine = Engine::new(4, 2);
        let first = engine.accept(key(40000, "198.51.100.1:7"), now).unwrap();
        let second = engine.accept(key(40000, "198.51.100.2:9"), now).unwrap();
        assert!(first.created && first.association_created);
        assert!(second.created && !second.association_created);
        assert_eq!(engine.active_flows(), 2);
        assert_eq!(engine.active_associations(), 1);
    }

    #[test]
    fn limits_refuse_only_new_resources() {
        let now = Instant::now();
        let mut engine = Engine::new(2, 1);
        let first_key = key(40000, "198.51.100.1:7");
        let first = engine.accept(first_key, now).unwrap();
        assert_eq!(engine.accept(first_key, now).unwrap().id, first.id);
        engine.accept(key(40000, "198.51.100.2:9"), now).unwrap();
        assert_eq!(
            engine.accept(key(40000, "198.51.100.3:11"), now),
            Err(AcceptError::FlowLimit)
        );
        engine.remove(first.id);
        assert_eq!(
            engine.accept(key(40001, "198.51.100.3:11"), now),
            Err(AcceptError::AssociationLimit)
        );
    }

    #[test]
    fn bidirectional_activity_promotes_stream_timeout() {
        let now = Instant::now();
        let mut engine = Engine::new(1, 1);
        let accepted = engine.accept(key(40000, "198.51.100.1:7"), now).unwrap();
        assert_eq!(
            engine.flow(accepted.id).unwrap().timeout_class(),
            TimeoutClass::OneShot
        );
        engine.record_outbound(accepted.id, now);
        engine.record_inbound(accepted.id, now);
        engine.record_inbound(accepted.id, now);
        assert_eq!(
            engine.flow(accepted.id).unwrap().timeout_class(),
            TimeoutClass::Stream
        );
        assert!(engine.expire(now + ONE_SHOT_TIMEOUT).is_empty());
        assert_eq!(engine.expire(now + STREAM_TIMEOUT), vec![accepted.id]);
        assert_eq!(engine.active_associations(), 0);
    }

    #[test]
    fn dns_flow_uses_short_timeout() {
        let now = Instant::now();
        let mut engine = Engine::new(1, 1);
        let accepted = engine.accept(key(40000, "198.51.100.53:53"), now).unwrap();
        assert_eq!(
            engine.flow(accepted.id).unwrap().timeout_class(),
            TimeoutClass::Dns
        );
        assert_eq!(engine.expire(now + DNS_TIMEOUT), vec![accepted.id]);
    }

    #[test]
    fn mixed_families_are_rejected() {
        let mut engine = Engine::new(1, 1);
        assert_eq!(
            engine.accept(
                FlowKey {
                    source: "192.0.2.2:1234".parse().unwrap(),
                    target: "[2001:db8::1]:7".parse().unwrap(),
                },
                Instant::now(),
            ),
            Err(AcceptError::FamilyMismatch)
        );
    }
}
