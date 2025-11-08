// Numan Thabit 2025
// sched/drr.rs - DRR with floors and quantum

use std::collections::VecDeque;
use std::hash::Hash;

use ahash::AHashMap;

/// State maintained for an individual Deficit Round Robin flow.
#[derive(Debug)]
struct FlowState {
    backlog_bytes: u64,
    deficit: u64,
    quantum: u64,
    active: bool,
}

impl FlowState {
    fn new(quantum: u64) -> Self {
        Self {
            backlog_bytes: 0,
            deficit: 0,
            quantum: quantum.max(1),
            active: false,
        }
    }
}

/// Deficit Round Robin scheduler used to arbitrate between competing flows.
#[derive(Debug)]
pub struct DeficitRoundRobin<K>
where
    K: Eq + Hash + Clone,
{
    flows: AHashMap<K, FlowState>,
    order: VecDeque<K>,
    min_quantum: u64,
}

impl<K> DeficitRoundRobin<K>
where
    K: Eq + Hash + Clone,
{
    /// Creates an empty DRR scheduler.
    pub fn new(min_quantum: u64) -> Self {
        Self {
            flows: AHashMap::default(),
            order: VecDeque::new(),
            min_quantum: min_quantum.max(1),
        }
    }

    /// Inserts or updates a flow with the specified quantum.
    pub fn upsert_flow(&mut self, key: K, quantum: u64) {
        let quantum = quantum.max(self.min_quantum);
        self.flows
            .entry(key.clone())
            .and_modify(|flow| flow.quantum = quantum)
            .or_insert_with(|| {
                self.order.push_back(key.clone());
                FlowState::new(quantum)
            });
    }

    /// Removes a flow from scheduling.
    pub fn remove_flow(&mut self, key: &K) {
        self.flows.remove(key);
        self.order.retain(|entry| entry != key);
    }

    /// Updates the backlog for a flow, activating it when bytes are queued.
    pub fn set_backlog(&mut self, key: &K, backlog_bytes: u64) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.backlog_bytes = backlog_bytes;
            flow.active = backlog_bytes > 0;
            if flow.active && !self.order.contains(key) {
                self.order.push_back(key.clone());
            }
        }
    }

    /// Returns `true` if any flow currently has backlog.
    pub fn has_backlog(&self) -> bool {
        self.flows.values().any(|flow| flow.backlog_bytes > 0)
    }

    /// Attempts to select the next flow that can transmit `packet_len` bytes.
    pub fn pop_next(&mut self, packet_len: u64) -> Option<K> {
        if self.order.is_empty() || packet_len == 0 {
            return None;
        }

        let mut rotations = 0;
        let len = self.order.len();

        while rotations < len {
            let key = self.order.pop_front()?;
            if let Some(flow) = self.flows.get_mut(&key) {
                if !flow.active {
                    flow.deficit = 0;
                    rotations += 1;
                    continue;
                }

                flow.deficit = flow.deficit.saturating_add(flow.quantum);
                if flow.backlog_bytes >= packet_len && flow.deficit >= packet_len {
                    flow.deficit -= packet_len;
                    flow.backlog_bytes -= packet_len;
                    if flow.backlog_bytes > 0 {
                        self.order.push_back(key.clone());
                    } else {
                        flow.active = false;
                    }
                    return Some(key);
                }
            }

            self.order.push_back(key);
            rotations += 1;
        }

        None
    }

    /// Returns the deficit for a given flow (mainly for debugging/metrics).
    pub fn deficit(&self, key: &K) -> Option<u64> {
        self.flows.get(key).map(|flow| flow.deficit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_round_robin() {
        let mut drr = DeficitRoundRobin::new(1500);
        drr.upsert_flow("a", 1500);
        drr.upsert_flow("b", 1500);
        drr.set_backlog(&"a", 3000);
        drr.set_backlog(&"b", 1500);

        let first = drr.pop_next(1500).expect("flow");
        assert_eq!(first, "a");
        let second = drr.pop_next(1500).expect("flow");
        assert_eq!(second, "b");
        let third = drr.pop_next(1500).expect("flow");
        assert_eq!(third, "a");
        assert!(drr.pop_next(1500).is_none());
    }

    #[test]
    fn skips_when_deficit_insufficient() {
        let mut drr = DeficitRoundRobin::new(1000);
        drr.upsert_flow(1u8, 1000);
        drr.set_backlog(&1, 2000);
        assert!(drr.pop_next(1500).is_none());
        let flow = drr.pop_next(1000).expect("flow");
        assert_eq!(flow, 1);
    }
}
