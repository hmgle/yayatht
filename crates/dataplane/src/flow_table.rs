use std::num::NonZeroU32;

const SLOT_BITS: u64 = 20;
const RESOURCE_BITS: u64 = 7;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const RESOURCE_MASK: u64 = (1 << RESOURCE_BITS) - 1;
const SIDE_SHIFT: u64 = SLOT_BITS + RESOURCE_BITS;
const GENERATION_SHIFT: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Resource {
    UpstreamSocket = 1,
    Tap = 2,
    Timer = 3,
    Control = 4,
    DnsUpstream = 5,
    UdpSocket = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpollToken(u64);

impl EpollToken {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn flow(id: FlowId, resource: Resource, target_side: bool) -> Option<Self> {
        if u64::from(id.slot) > SLOT_MASK || id.generation == 0 {
            return None;
        }
        let value = (u64::from(id.generation) << GENERATION_SHIFT)
            | u64::from(id.slot)
            | ((resource as u64 & RESOURCE_MASK) << SLOT_BITS)
            | (u64::from(target_side) << SIDE_SHIFT);
        Some(Self(value))
    }

    #[must_use]
    pub const fn global(resource: Resource) -> Self {
        Self((resource as u64 & RESOURCE_MASK) << SLOT_BITS)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub fn decode(self) -> Option<(Option<FlowId>, Resource, bool)> {
        if self.0 & 0xf000_0000 != 0 {
            return None;
        }
        let resource = match (self.0 >> SLOT_BITS) & RESOURCE_MASK {
            1 => Resource::UpstreamSocket,
            2 => Resource::Tap,
            3 => Resource::Timer,
            4 => Resource::Control,
            5 => Resource::DnsUpstream,
            6 => Resource::UdpSocket,
            _ => return None,
        };
        let generation = (self.0 >> GENERATION_SHIFT) as u32;
        let slot = (self.0 & SLOT_MASK) as u32;
        let flow = NonZeroU32::new(generation).map(|generation| FlowId {
            slot,
            generation: generation.get(),
        });
        Some((flow, resource, self.0 & (1 << SIDE_SHIFT) != 0))
    }
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
    retired: bool,
}

pub struct FlowTable<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    deferred: Vec<FlowId>,
}

impl<T> FlowTable<T> {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= 1 << SLOT_BITS);
        let slots = (0..capacity)
            .map(|_| Slot {
                generation: 1,
                value: None,
                retired: false,
            })
            .collect();
        let free = (0..capacity as u32).rev().collect();
        Self {
            slots,
            free,
            deferred: Vec::new(),
        }
    }

    pub fn insert(&mut self, value: T) -> Result<FlowId, T> {
        let Some(slot_index) = self.free.pop() else {
            return Err(value);
        };
        let slot = &mut self.slots[slot_index as usize];
        if slot.retired {
            return Err(value);
        }
        slot.value = Some(value);
        Ok(FlowId {
            slot: slot_index,
            generation: slot.generation,
        })
    }

    pub fn get(&self, id: FlowId) -> Option<&T> {
        let slot = self.slots.get(id.slot as usize)?;
        (slot.generation == id.generation)
            .then_some(slot.value.as_ref())
            .flatten()
    }

    pub fn get_mut(&mut self, id: FlowId) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.slot as usize)?;
        (slot.generation == id.generation)
            .then_some(slot.value.as_mut())
            .flatten()
    }

    pub fn defer_remove(&mut self, id: FlowId) {
        if self.get(id).is_some() && !self.deferred.contains(&id) {
            self.deferred.push(id);
        }
    }

    #[must_use]
    pub fn active_ids(&self) -> Vec<FlowId> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| {
                entry.value.as_ref().map(|_| FlowId {
                    slot: slot as u32,
                    generation: entry.generation,
                })
            })
            .collect()
    }

    pub fn flush_deferred(&mut self) -> Vec<T> {
        let ids = std::mem::take(&mut self.deferred);
        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let slot = &mut self.slots[id.slot as usize];
            if slot.generation != id.generation {
                continue;
            }
            if let Some(value) = slot.value.take() {
                removed.push(value);
            }
            if let Some(next) = slot.generation.checked_add(1) {
                slot.generation = next;
                self.free.push(id.slot);
            } else {
                slot.retired = true;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_slot_is_not_reused() {
        let mut table = FlowTable::with_capacity(1);
        let first = table.insert(1).unwrap();
        table.defer_remove(first);
        assert_eq!(table.insert(2), Err(2));
        assert_eq!(table.flush_deferred(), vec![1]);
        let second = table.insert(2).unwrap();
        assert_eq!(first.slot, second.slot);
        assert_ne!(first.generation, second.generation);
        assert!(table.get(first).is_none());
    }

    #[test]
    fn token_round_trip() {
        let id = FlowId {
            slot: 7,
            generation: 9,
        };
        let token = EpollToken::flow(id, Resource::UpstreamSocket, true).unwrap();
        assert_eq!(
            token.decode(),
            Some((Some(id), Resource::UpstreamSocket, true))
        );
        let udp = EpollToken::flow(id, Resource::UdpSocket, true).unwrap();
        assert_eq!(udp.decode(), Some((Some(id), Resource::UdpSocket, true)));
    }
}
