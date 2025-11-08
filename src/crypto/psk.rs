// Numan Thabit 2025
// crypto/psk.rs - PSK store and rotation with overlap
use std::collections::BTreeSet;

use ahash::AHashMap;
use thiserror::Error;

/// Fixed-size pre-shared key used for zero-RTT authentication paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PskEntry {
    pub id: u32,
    pub key: [u8; 32],
}

/// Errors returned by the PSK store when rotation invariants are violated.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PskError {
    #[error("epoch {0} is older than or equal to the current epoch")]
    EpochRewind(u64),
    #[error("epoch {0} already staged for rotation")]
    DuplicateEpoch(u64),
    #[error("no keys are staged for rotation")]
    NoPendingRotation,
}

/// PSK store maintaining the currently active epoch plus a staged successor.
#[derive(Debug, Clone)]
pub struct PskStore {
    current_epoch: u64,
    current: AHashMap<u32, [u8; 32]>,
    next: Option<(u64, AHashMap<u32, [u8; 32]>)>,
}

impl PskStore {
    /// Creates a store populated with the provided keys for `epoch`.
    pub fn new(epoch: u64, keys: impl IntoIterator<Item = PskEntry>) -> Self {
        let mut current = AHashMap::default();
        for entry in keys {
            current.insert(entry.id, entry.key);
        }
        Self {
            current_epoch: epoch,
            current,
            next: None,
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Stages keys for a future epoch.
    pub fn stage_rotation(
        &mut self,
        epoch: u64,
        keys: impl IntoIterator<Item = PskEntry>,
    ) -> Result<(), PskError> {
        if epoch <= self.current_epoch {
            return Err(PskError::EpochRewind(epoch));
        }

        if let Some((next_epoch, _)) = &self.next {
            if *next_epoch == epoch {
                return Err(PskError::DuplicateEpoch(epoch));
            }
        }

        let mut staged = AHashMap::default();
        for entry in keys {
            staged.insert(entry.id, entry.key);
        }
        self.next = Some((epoch, staged));
        Ok(())
    }

    /// Promotes the staged keys when the epoch advances beyond or equal to the staged epoch.
    pub fn rotate(&mut self, epoch: u64) -> Result<bool, PskError> {
        let (next_epoch, next_keys) = match self.next.take() {
            Some(pair) => pair,
            None => return Err(PskError::NoPendingRotation),
        };

        if epoch < next_epoch {
            // Not yet eligible; preserve staged state.
            self.next = Some((next_epoch, next_keys));
            return Ok(false);
        }

        self.current_epoch = next_epoch;
        self.current = next_keys;
        Ok(true)
    }

    /// Resolves a PSK by identifier, searching both current and staged epochs.
    pub fn resolve(&self, id: u32) -> Option<&[u8; 32]> {
        self.current
            .get(&id)
            .or_else(|| self.next.as_ref().and_then(|(_, map)| map.get(&id)))
    }

    /// Returns the currently accepted PSK identifiers (current + staged).
    pub fn accepted_ids(&self) -> BTreeSet<u32> {
        let mut ids = BTreeSet::new();
        ids.extend(self.current.keys().copied());
        if let Some((_, staged)) = &self.next {
            ids.extend(staged.keys().copied());
        }
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32) -> PskEntry {
        PskEntry {
            id,
            key: [id as u8; 32],
        }
    }

    #[test]
    fn rotate_promotes_next_epoch() {
        let mut store = PskStore::new(1, [entry(1)]);
        store.stage_rotation(2, [entry(2)]).expect("stage");
        assert!(store.resolve(2).is_some());
        assert_eq!(store.rotate(2).expect("rotate"), true);
        assert!(store.resolve(1).is_none());
        assert!(store.resolve(2).is_some());
    }

    #[test]
    fn rotation_not_ready() {
        let mut store = PskStore::new(1, [entry(1)]);
        store.stage_rotation(3, [entry(3)]).expect("stage");
        assert_eq!(store.rotate(2).expect("rotate"), false);
        assert!(store.resolve(3).is_some());
    }

    #[test]
    fn accepted_ids_union() {
        let mut store = PskStore::new(1, [entry(5), entry(7)]);
        store.stage_rotation(2, [entry(1)]).expect("stage");
        let ids = store.accepted_ids();
        assert!(ids.contains(&5));
        assert!(ids.contains(&1));
    }
}
