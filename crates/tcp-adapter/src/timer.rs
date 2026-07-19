// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerKind {
    Retransmit,
    Connect,
    Idle,
    TimeWait,
    ZeroWindowProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerEntry<T> {
    pub key: T,
    pub kind: TimerKind,
    pub deadline: Instant,
    pub sequence: u32,
}

pub struct TimerWheel<T> {
    epoch: Instant,
    tick: Duration,
    cursor: u64,
    buckets: Vec<VecDeque<TimerEntry<T>>>,
}

impl<T: Copy> TimerWheel<T> {
    #[must_use]
    pub fn new(epoch: Instant, tick: Duration, buckets: usize) -> Self {
        assert!(buckets > 0);
        Self {
            epoch,
            tick,
            cursor: 0,
            buckets: (0..buckets).map(|_| VecDeque::new()).collect(),
        }
    }

    pub fn schedule(&mut self, entry: TimerEntry<T>) {
        let elapsed = entry.deadline.saturating_duration_since(self.epoch);
        let tick_nanos = self.tick.as_nanos().max(1);
        let ticks = (elapsed.as_nanos() / tick_nanos) as u64;
        let slot = (ticks as usize) % self.buckets.len();
        self.buckets[slot].push_back(entry);
    }

    pub fn expire(&mut self, now: Instant, out: &mut Vec<TimerEntry<T>>) {
        let elapsed = now.saturating_duration_since(self.epoch);
        let target = (elapsed.as_nanos() / self.tick.as_nanos().max(1)) as u64;
        while self.cursor <= target {
            let slot = (self.cursor as usize) % self.buckets.len();
            let count = self.buckets[slot].len();
            for _ in 0..count {
                let entry = self.buckets[slot].pop_front().expect("known bucket length");
                if entry.deadline <= now {
                    out.push(entry);
                } else {
                    self.schedule(entry);
                }
            }
            self.cursor = self.cursor.saturating_add(1);
        }
    }
}
