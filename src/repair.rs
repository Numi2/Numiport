// Numan Thabit 2025
// repair.rs - repair request/serve helpers
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepairKey {
    pub slot: u64,
    pub index: u32,
}

#[derive(Debug, Clone)]
struct RepairEntry {
    last_request: Instant,
    attempts: u8,
}

#[derive(Debug, Clone)]
pub struct RepairTracker {
    ttl: Duration,
    entries: AHashMap<RepairKey, RepairEntry>,
}

impl RepairTracker {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: AHashMap::default(),
        }
    }

    /// Returns `true` when a repair request should be sent.
    pub fn should_request(&mut self, key: RepairKey, now: Instant) -> bool {
        match self.entries.get_mut(&key) {
            Some(entry) => {
                if now.duration_since(entry.last_request) >= self.ttl {
                    entry.last_request = now;
                    entry.attempts = entry.attempts.saturating_add(1);
                    true
                } else {
                    false
                }
            }
            None => {
                self.entries.insert(
                    key,
                    RepairEntry {
                        last_request: now,
                        attempts: 1,
                    },
                );
                true
            }
        }
    }

    /// Marks the repair as satisfied, removing it from dedupe tracking.
    pub fn satisfy(&mut self, key: &RepairKey) {
        self.entries.remove(key);
    }

    /// Purges entries that have not been touched within 4× TTL, preventing growth.
    pub fn purge(&mut self, now: Instant) {
        let ttl4 = self.ttl.checked_mul(4).unwrap_or(Duration::MAX);
        self.entries
            .retain(|_, entry| now.duration_since(entry.last_request) <= ttl4);
    }

    pub fn attempts(&self, key: &RepairKey) -> Option<u8> {
        self.entries.get(key).map(|entry| entry.attempts)
    }
}

#[derive(Debug, Clone)]
pub struct RepairPayload {
    frame: Bytes,
    stored_at: Instant,
}

impl RepairPayload {
    pub fn new(frame: Bytes, stored_at: Instant) -> Self {
        Self { frame, stored_at }
    }

    pub fn frame(&self) -> &Bytes {
        &self.frame
    }

    pub fn stored_at(&self) -> Instant {
        self.stored_at
    }
}

#[derive(Debug, Default)]
pub struct RecentRepairStorage {
    capacity: usize,
    ttl: Duration,
    entries: AHashMap<RepairKey, RepairPayload>,
    order: VecDeque<RepairKey>,
}

impl RecentRepairStorage {
    pub fn with_capacity(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "recent repair storage requires capacity > 0");
        Self {
            capacity,
            ttl,
            entries: AHashMap::default(),
            order: VecDeque::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn fetch(&self, key: &RepairKey) -> Option<&RepairPayload> {
        self.entries.get(key)
    }

    pub fn remove(&mut self, key: &RepairKey) -> Option<RepairPayload> {
        if let Some(payload) = self.entries.remove(key) {
            if let Some(pos) = self.order.iter().position(|existing| existing == key) {
                self.order.remove(pos);
            }
            Some(payload)
        } else {
            None
        }
    }

    pub fn prune(&mut self, now: Instant) -> Vec<(RepairKey, RepairPayload)> {
        let mut evicted = Vec::new();
        while let Some(key) = self.order.front().copied() {
            let expired = self
                .entries
                .get(&key)
                .map(|payload| now.duration_since(payload.stored_at) > self.ttl)
                .unwrap_or(true);
            if expired {
                self.order.pop_front();
                if let Some(payload) = self.entries.remove(&key) {
                    evicted.push((key, payload));
                }
            } else {
                break;
            }
        }
        evicted
    }

    pub fn store(
        &mut self,
        key: RepairKey,
        payload: RepairPayload,
    ) -> Option<(RepairKey, RepairPayload)> {
        if self.entries.contains_key(&key) {
            if let Some(pos) = self.order.iter().position(|existing| *existing == key) {
                self.order.remove(pos);
            }
        }
        self.entries.insert(key, payload);
        self.order.push_back(key);
        if self.entries.len() > self.capacity {
            if let Some(evicted_key) = self.order.pop_front() {
                if let Some(evicted_payload) = self.entries.remove(&evicted_key) {
                    return Some((evicted_key, evicted_payload));
                }
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct DeepRepairStorage {
    max_slots: usize,
    entries: BTreeMap<u64, AHashMap<u32, RepairPayload>>,
}

impl DeepRepairStorage {
    pub fn with_max_slots(max_slots: usize) -> Self {
        assert!(max_slots > 0, "deep repair storage requires max_slots > 0");
        Self {
            max_slots,
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(|slot| slot.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn slot_count(&self) -> usize {
        self.entries.len()
    }

    pub fn fetch(&self, key: &RepairKey) -> Option<&RepairPayload> {
        self.entries
            .get(&key.slot)
            .and_then(|slot| slot.get(&key.index))
    }

    pub fn remove(&mut self, key: &RepairKey) -> Option<RepairPayload> {
        if let Some(slot) = self.entries.get_mut(&key.slot) {
            let removed = slot.remove(&key.index);
            if slot.is_empty() {
                self.entries.remove(&key.slot);
            }
            removed
        } else {
            None
        }
    }

    pub fn store(&mut self, key: RepairKey, payload: RepairPayload) {
        let slot = self.entries.entry(key.slot).or_default();
        slot.insert(key.index, payload);
        while self.entries.len() > self.max_slots {
            if let Some(oldest_slot) = self.entries.keys().next().copied() {
                self.entries.remove(&oldest_slot);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairInventory {
    pub recent_entries: usize,
    pub deep_entries: usize,
    pub deep_slots: usize,
}

#[derive(Debug)]
pub struct RepairService {
    tracker: RepairTracker,
    recent: RecentRepairStorage,
    deep: DeepRepairStorage,
}

impl RepairService {
    pub fn new(
        ttl: Duration,
        recent_capacity: usize,
        recent_ttl: Duration,
        deep_slots: usize,
    ) -> Self {
        Self {
            tracker: RepairTracker::new(ttl),
            recent: RecentRepairStorage::with_capacity(recent_capacity, recent_ttl),
            deep: DeepRepairStorage::with_max_slots(deep_slots),
        }
    }

    pub fn should_request(&mut self, key: RepairKey, now: Instant) -> bool {
        self.tracker.should_request(key, now)
    }

    pub fn record_frame(&mut self, key: RepairKey, frame: Bytes, now: Instant) {
        for (expired_key, expired_payload) in self.recent.prune(now) {
            self.deep.store(expired_key, expired_payload);
        }

        let payload = RepairPayload::new(frame, now);
        if let Some((evicted_key, evicted_payload)) = self.recent.store(key, payload.clone()) {
            self.deep.store(evicted_key, evicted_payload);
        }
        self.deep.store(key, payload);
    }

    pub fn fetch(&self, key: &RepairKey) -> Option<Bytes> {
        if let Some(payload) = self.recent.fetch(key) {
            return Some(payload.frame().clone());
        }
        self.deep.fetch(key).map(|payload| payload.frame().clone())
    }

    pub fn satisfy(&mut self, key: &RepairKey) {
        self.tracker.satisfy(key);
        self.recent.remove(key);
        self.deep.remove(key);
    }

    pub fn purge(&mut self, now: Instant) {
        self.tracker.purge(now);
        for (expired_key, expired_payload) in self.recent.prune(now) {
            self.deep.store(expired_key, expired_payload);
        }
    }

    pub fn inventory(&self) -> RepairInventory {
        RepairInventory {
            recent_entries: self.recent.len(),
            deep_entries: self.deep.len(),
            deep_slots: self.deep.slot_count(),
        }
    }
}

impl Default for RepairService {
    fn default() -> Self {
        Self::new(
            Duration::from_millis(20),
            256,
            Duration::from_millis(250),
            512,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_duplicate_requests() {
        let mut tracker = RepairTracker::new(Duration::from_millis(50));
        let key = RepairKey { slot: 12, index: 1 };
        let now = Instant::now();
        assert!(tracker.should_request(key, now));
        assert!(!tracker.should_request(key, now));
        assert!(tracker.should_request(key, now + Duration::from_millis(60)));
    }

    #[test]
    fn service_promotes_into_deep_storage() {
        let mut service =
            RepairService::new(Duration::from_millis(10), 2, Duration::from_millis(5), 8);
        let now = Instant::now();
        for idx in 0..3 {
            let key = RepairKey {
                slot: 42,
                index: idx,
            };
            service.record_frame(key, Bytes::from_static(b"payload"), now);
        }
        let inventory = service.inventory();
        assert_eq!(inventory.recent_entries, 2);
        assert_eq!(inventory.deep_entries, 3);
        assert!(service.fetch(&RepairKey { slot: 42, index: 0 }).is_some());
    }

    #[test]
    fn service_moves_expired_entries() {
        let mut service =
            RepairService::new(Duration::from_millis(10), 4, Duration::from_millis(1), 8);
        let now = Instant::now();
        let key = RepairKey { slot: 7, index: 9 };
        service.record_frame(key, Bytes::from_static(b"late"), now);
        service.purge(now + Duration::from_millis(5));
        assert!(service.fetch(&key).is_some());
    }
}
