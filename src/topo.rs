// Numan Thabit 2025
// topo.rs - neighbor TTLs and diversity guard
use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use rand::Rng;

#[derive(Debug, Clone)]
struct NeighborEntry<P> {
    peers: Vec<P>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct TopologyCache<K, P>
where
    K: Eq + Hash + Clone,
    P: Eq + Hash + Clone,
{
    base_ttl: Duration,
    ttl_jitter: Duration,
    min_diversity: usize,
    history_window: usize,
    neighbors: AHashMap<K, NeighborEntry<P>>,
    parent_history: VecDeque<P>,
}

impl<K, P> TopologyCache<K, P>
where
    K: Eq + Hash + Clone,
    P: Eq + Hash + Clone,
{
    pub fn new(
        base_ttl: Duration,
        ttl_jitter: Duration,
        min_diversity: usize,
        history_window: usize,
    ) -> Self {
        Self {
            base_ttl,
            ttl_jitter,
            min_diversity,
            history_window,
            neighbors: AHashMap::default(),
            parent_history: VecDeque::new(),
        }
    }

    pub fn upsert_neighbors(&mut self, key: K, peers: Vec<P>, now: Instant) {
        let ttl = self.random_ttl();
        self.neighbors.insert(
            key,
            NeighborEntry {
                peers,
                expires_at: now + ttl,
            },
        );
    }

    pub fn neighbors(&self, key: &K, now: Instant) -> Option<&[P]> {
        self.neighbors.get(key).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.peers.as_slice())
            } else {
                None
            }
        })
    }

    pub fn needs_refresh(&self, key: &K, now: Instant) -> bool {
        match self.neighbors.get(key) {
            Some(entry) => entry.expires_at <= now,
            None => true,
        }
    }

    pub fn record_parent(&mut self, parent: P) {
        if self.parent_history.len() >= self.history_window {
            self.parent_history.pop_front();
        }
        self.parent_history.push_back(parent);
    }

    pub fn diversity_ok(&self) -> bool {
        let unique: HashSet<_> = self.parent_history.iter().cloned().collect();
        unique.len() >= self.min_diversity
    }

    pub fn force_refresh(&mut self, key: &K, now: Instant) {
        if let Some(entry) = self.neighbors.get_mut(key) {
            entry.expires_at = now;
        }
    }

    fn random_ttl(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(Duration::ZERO..=self.ttl_jitter);
        self.base_ttl + jitter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_on_ttl_expiry() {
        let mut topo = TopologyCache::new(Duration::from_secs(1), Duration::from_millis(200), 2, 4);
        let now = Instant::now();
        topo.upsert_neighbors(1u8, vec![2u8, 3], now);
        assert!(topo.neighbors(&1, now).is_some());
        assert!(topo.needs_refresh(&1, now + Duration::from_secs(5)));
    }

    #[test]
    fn diversity_guard_counts_unique_parents() {
        let mut topo: TopologyCache<u8, u8> =
            TopologyCache::new(Duration::from_secs(1), Duration::from_secs(1), 3, 6);
        topo.record_parent(1u8);
        topo.record_parent(1u8);
        topo.record_parent(2u8);
        topo.record_parent(3u8);
        assert!(topo.diversity_ok());
    }
}
