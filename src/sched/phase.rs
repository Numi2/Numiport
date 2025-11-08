// Numan Thabit 2025
// sched/phase.rs - per-peer phase desync

use std::hash::{Hash, Hasher};
use std::time::Duration;

use ahash::AHasher;

/// Computes deterministic phase offsets to avoid synchronized bursts.
#[derive(Debug, Clone)]
pub struct PhaseDesync {
    bursts_per_slot: u32,
}

impl PhaseDesync {
    pub fn new(bursts_per_slot: u32) -> Self {
        Self {
            bursts_per_slot: bursts_per_slot.max(1),
        }
    }

    /// Returns the phase offset for a peer given the slot duration.
    pub fn phase_for_peer<P: Hash>(&self, peer_id: &P, slot: Duration) -> Duration {
        let mut hasher = AHasher::default();
        peer_id.hash(&mut hasher);
        let hash = hasher.finish();
        let slice = slot / self.bursts_per_slot;
        let offset_burst = (hash % self.bursts_per_slot as u64) as u32;
        slice * offset_burst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributes_across_bursts() {
        let desync = PhaseDesync::new(8);
        let slot = Duration::from_millis(400);
        let mut offsets = Vec::new();
        for peer in 0..16u64 {
            offsets.push(desync.phase_for_peer(&peer, slot));
        }
        offsets.sort();
        offsets.dedup();
        assert!(offsets.len() > 4);
    }
}
