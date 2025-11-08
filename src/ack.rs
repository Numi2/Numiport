// Numan Thabit 2025
// ack.rs - RLE ACK encoder/decoder and replay window

use std::collections::{HashMap, VecDeque};

use bitvec::prelude::*;
use thiserror::Error;

/// Inclusive acknowledgement range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub start: u32,
    pub end: u32,
}

impl AckRange {
    pub fn new(start: u32, end: u32) -> Self {
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        Self { start, end }
    }

    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Error returned while encoding or decoding ACK payloads.
#[derive(Debug, Error)]
pub enum AckError {
    #[error("ack payload truncated")]
    Truncated,
    #[error("ack range overflow")]
    Overflow,
    #[error("invalid ack payload length {0}")]
    InvalidLength(usize),
}

/// Builder for encoded acknowledgement payloads.
#[derive(Debug, Clone)]
pub struct AckEncoder {
    ranges: Vec<AckRange>,
    max_bytes: usize,
}

impl AckEncoder {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            ranges: Vec::new(),
            max_bytes,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[AckRange] {
        &self.ranges
    }

    pub fn add(&mut self, seq: u32) {
        self.add_range(seq, seq);
    }

    pub fn add_range(&mut self, start: u32, end: u32) {
        let mut new_start = start.min(end);
        let mut new_end = start.max(end);

        let mut idx = 0;
        while idx < self.ranges.len() {
            let range = &self.ranges[idx];
            if new_end.saturating_add(1) < range.start {
                break;
            }
            if new_start > range.end.saturating_add(1) {
                idx += 1;
                continue;
            }

            new_start = new_start.min(range.start);
            new_end = new_end.max(range.end);
            self.ranges.remove(idx);
        }

        self.ranges.insert(idx, AckRange::new(new_start, new_end));
    }

    pub fn encode(&self) -> Vec<u8> {
        if self.ranges.is_empty() {
            return Vec::new();
        }

        let mut encoded = Vec::with_capacity(self.max_bytes.min(self.ranges.len() * 6));

        for range in &self.ranges {
            let mut remaining = range.len();
            let mut cursor = range.start;

            while remaining > 0 {
                let chunk = remaining.min(u16::MAX as u32);
                let required = encoded.len().saturating_add(6);
                if required > self.max_bytes {
                    return encoded;
                }

                encoded.extend_from_slice(&cursor.to_le_bytes());
                encoded.extend_from_slice(&(chunk as u16).to_le_bytes());

                cursor = cursor.saturating_add(chunk);
                remaining = remaining.saturating_sub(chunk);
            }
        }

        encoded
    }
}

/// Decodes acknowledgement ranges from wire payloads.
pub struct AckDecoder<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> AckDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    pub fn decode(mut self) -> Result<Vec<AckRange>, AckError> {
        if self.buf.len() % 6 != 0 {
            return Err(AckError::InvalidLength(self.buf.len()));
        }

        let mut ranges = Vec::new();

        while self.offset < self.buf.len() {
            let remaining = self.buf.len().saturating_sub(self.offset);
            if remaining < 6 {
                return Err(AckError::Truncated);
            }

            let start = u32::from_le_bytes(
                self.buf[self.offset..self.offset + 4]
                    .try_into()
                    .expect("slice length checked"),
            );
            let run = u16::from_le_bytes(
                self.buf[self.offset + 4..self.offset + 6]
                    .try_into()
                    .expect("slice length checked"),
            ) as u32;
            self.offset += 6;

            if run == 0 {
                return Err(AckError::InvalidLength(0));
            }

            let end = start.checked_add(run - 1).ok_or(AckError::Overflow)?;
            ranges.push(AckRange { start, end });
        }

        Ok(ranges)
    }
}

const BITS_PER_BUCKET: usize = 256;
const MAX_BUCKETS_PER_STREAM: usize = 8;

#[derive(Debug)]
struct ReplayBucket {
    base: u32,
    bits: BitVec<u8, Lsb0>,
}

impl ReplayBucket {
    fn new(base: u32) -> Self {
        let mut bits = BitVec::<u8, Lsb0>::with_capacity(BITS_PER_BUCKET);
        bits.resize(BITS_PER_BUCKET, false);
        Self { base, bits }
    }

    fn covers(&self, seq: u32) -> bool {
        seq >= self.base && seq < self.base.saturating_add(BITS_PER_BUCKET as u32)
    }

    fn test_and_set(&mut self, seq: u32) -> bool {
        if !self.covers(seq) {
            return false;
        }
        let offset = (seq - self.base) as usize;
        if self.bits[offset] {
            false
        } else {
            self.bits.set(offset, true);
            true
        }
    }
}

#[derive(Debug)]
struct StreamBuckets {
    buckets: Vec<ReplayBucket>,
}

impl StreamBuckets {
    fn new() -> Self {
        Self {
            buckets: Vec::new(),
        }
    }

    fn get_or_insert(&mut self, seq: u32) -> &mut ReplayBucket {
        let base = align_base(seq);
        if let Some(idx) = self.buckets.iter().position(|b| b.base == base) {
            return &mut self.buckets[idx];
        }

        let bucket = ReplayBucket::new(base);
        self.buckets.push(bucket);
        self.buckets.sort_by_key(|b| b.base);

        if self.buckets.len() > MAX_BUCKETS_PER_STREAM {
            self.buckets.remove(0);
        }

        self.buckets
            .iter_mut()
            .find(|b| b.base == base)
            .expect("bucket exists")
    }

    fn test_and_set(&mut self, seq: u32) -> bool {
        let bucket = self.get_or_insert(seq);
        bucket.test_and_set(seq)
    }
}

#[derive(Debug)]
struct SlotEntry {
    slot: u64,
    streams: HashMap<u32, StreamBuckets>,
}

impl SlotEntry {
    fn new(slot: u64) -> Self {
        Self {
            slot,
            streams: HashMap::new(),
        }
    }

    fn test_and_set(&mut self, stream: u32, seq: u32) -> bool {
        let buckets = self
            .streams
            .entry(stream)
            .or_insert_with(StreamBuckets::new);
        buckets.test_and_set(seq)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayOccupancy {
    pub slots: usize,
    pub streams: usize,
    pub sequences: usize,
}

/// Sliding replay filter over recent slots.
#[derive(Debug)]
pub struct ReplayWindow {
    capacity: usize,
    slots: VecDeque<SlotEntry>,
}

impl ReplayWindow {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be non-zero");
        Self {
            capacity,
            slots: VecDeque::new(),
        }
    }

    pub fn check_and_insert(&mut self, slot: u64, stream: u32, seq: u32) -> bool {
        self.evict_old_slots(slot);
        let entry = self.get_or_insert_slot(slot);
        entry.test_and_set(stream, seq)
    }

    fn evict_old_slots(&mut self, slot: u64) {
        while let Some(front) = self.slots.front() {
            if slot >= front.slot && (slot - front.slot) as usize >= self.capacity {
                self.slots.pop_front();
            } else {
                break;
            }
        }
    }

    fn get_or_insert_slot(&mut self, slot: u64) -> &mut SlotEntry {
        if let Some(pos) = self.slots.iter().position(|entry| entry.slot == slot) {
            return self.slots.get_mut(pos).expect("slot entry exists");
        }

        let entry = SlotEntry::new(slot);
        self.slots.push_back(entry);
        while self.slots.len() > self.capacity {
            self.slots.pop_front();
        }

        self.slots
            .iter_mut()
            .find(|entry| entry.slot == slot)
            .expect("slot entry inserted")
    }

    pub fn occupancy(&self) -> ReplayOccupancy {
        let mut occupancy = ReplayOccupancy {
            slots: self.slots.len(),
            ..ReplayOccupancy::default()
        };
        for slot in &self.slots {
            occupancy.streams += slot.streams.len();
            for buckets in slot.streams.values() {
                for bucket in &buckets.buckets {
                    occupancy.sequences += bucket.bits.iter().filter(|bit| **bit).count();
                }
            }
        }
        occupancy
    }
}

fn align_base(seq: u32) -> u32 {
    (seq / BITS_PER_BUCKET as u32) * BITS_PER_BUCKET as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_round_trip() {
        let mut encoder = AckEncoder::new(128);
        encoder.add_range(10, 15);
        encoder.add_range(20, 30);
        encoder.add(32);

        let bytes = encoder.encode();
        let decoded = AckDecoder::new(&bytes).decode().expect("decode");
        assert_eq!(decoded, encoder.ranges);
    }

    #[test]
    fn ack_encoder_respects_max_bytes() {
        let mut encoder = AckEncoder::new(6);
        encoder.add_range(0, 10);
        let bytes = encoder.encode();
        assert!(bytes.len() <= 6);
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let mut window = ReplayWindow::new(4);
        assert!(window.check_and_insert(1, 0, 10));
        assert!(!window.check_and_insert(1, 0, 10));
        assert!(window.check_and_insert(1, 0, 11));
    }

    #[test]
    fn replay_window_evicts_old_slots() {
        let mut window = ReplayWindow::new(2);
        assert!(window.check_and_insert(5, 1, 7));
        // Advance beyond capacity, causing eviction of slot 5.
        assert!(window.check_and_insert(7, 1, 7));
        assert!(window.check_and_insert(7, 1, 8));
        assert!(window.check_and_insert(8, 1, 7)); // slot 5 evicted, so seq 7 is new again
    }

    #[test]
    fn replay_window_reports_occupancy() {
        let mut window = ReplayWindow::new(4);
        assert!(window.check_and_insert(1, 0, 10));
        assert!(window.check_and_insert(1, 0, 11));
        let occupancy = window.occupancy();
        assert_eq!(occupancy.slots, 1);
        assert_eq!(occupancy.streams, 1);
        assert!(occupancy.sequences >= 2);
    }
}
// Numan Thabit 2025
// ack.rs - RLE ACKs and replay window
