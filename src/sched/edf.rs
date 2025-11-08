// Numan Thabit 2025
// sched/edf.rs - EDF queue with deadlines

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Timestamp expressed in nanoseconds relative to CLOCK_TAI.
pub type Timestamp = u128;

/// Item inserted into the EDF queue.
#[derive(Debug)]
struct EdfEntry<T> {
    deadline: Timestamp,
    order: u64,
    payload: T,
}

impl<T> PartialEq for EdfEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.order == other.order
    }
}

impl<T> Eq for EdfEntry<T> {}

impl<T> PartialOrd for EdfEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for EdfEntry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.deadline.cmp(&self.deadline) {
            Ordering::Equal => other.order.cmp(&self.order),
            ord => ord,
        }
    }
}

/// Earliest Deadline First queue storing arbitrary payloads keyed by deadline.
#[derive(Debug)]
pub struct EdfQueue<T> {
    heap: BinaryHeap<EdfEntry<T>>,
    counter: u64,
}

impl<T> Default for EdfQueue<T> {
    fn default() -> Self {
        Self {
            heap: BinaryHeap::new(),
            counter: 0,
        }
    }
}

impl<T> EdfQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new payload with the specified deadline.
    pub fn push(&mut self, deadline: Timestamp, payload: T) {
        let entry = EdfEntry {
            deadline,
            order: self.counter,
            payload,
        };
        self.counter = self.counter.wrapping_add(1);
        self.heap.push(entry);
    }

    /// Returns the payload with the earliest deadline when its deadline has passed.
    pub fn pop_due(&mut self, now: Timestamp) -> Option<T> {
        if let Some(entry) = self.heap.peek() {
            if entry.deadline <= now {
                return self.heap.pop().map(|entry| entry.payload);
            }
        }
        None
    }

    /// Returns the next deadline in the queue.
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.heap.peek().map(|entry| entry.deadline)
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edf_orders_by_deadline() {
        let mut queue = EdfQueue::new();
        queue.push(30, "late");
        queue.push(10, "early");
        queue.push(20, "mid");

        assert_eq!(queue.pop_due(10), Some("early"));
        assert_eq!(queue.pop_due(20), Some("mid"));
        assert!(queue.pop_due(25).is_none());
        assert_eq!(queue.pop_due(30), Some("late"));
    }
}
