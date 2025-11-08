// Numan Thabit 2025
// io/pmtu.rs - dPLPMTUD state machine
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PmtuState {
    min: u16,
    max: u16,
    current: u16,
    blacklist: BTreeSet<u16>,
    probe: Option<Probe>,
    last_probe: Option<Instant>,
    probe_interval: Duration,
}

#[derive(Debug, Clone)]
struct Probe {
    size: u16,
    deadline: Instant,
}

impl PmtuState {
    pub fn new(initial: u16, min: u16, max: u16, probe_interval: Duration) -> Self {
        let current = initial.clamp(min, max);
        Self {
            min,
            max,
            current,
            blacklist: BTreeSet::new(),
            probe: None,
            last_probe: None,
            probe_interval,
        }
    }

    pub fn current(&self) -> u16 {
        self.current
    }

    pub fn note_blackhole(&mut self, size: u16) {
        self.blacklist.insert(size);
        if size <= self.current {
            self.current = self.min;
        }
    }

    pub fn next_probe(&mut self, now: Instant) -> Option<u16> {
        if self.probe.is_some() {
            return self.probe.as_ref().map(|p| p.size);
        }
        if let Some(last) = self.last_probe {
            if now.duration_since(last) < self.probe_interval {
                return None;
            }
        }

        let candidate = self.next_candidate()?;
        let deadline = now + self.probe_interval;
        self.probe = Some(Probe { size: candidate, deadline });
        self.last_probe = Some(now);
        Some(candidate)
    }

    pub fn confirm_probe(&mut self, size: u16) {
        if let Some(probe) = &self.probe {
            if probe.size == size {
                self.current = self.current.max(size);
                self.probe = None;
            }
        }
    }

    pub fn probe_timed_out(&mut self, now: Instant) {
        if let Some(probe) = self.probe.take() {
            if now >= probe.deadline {
                self.blacklist.insert(probe.size);
            } else {
                self.probe = Some(probe);
            }
        }
    }

    fn next_candidate(&self) -> Option<u16> {
        let mut lo = self.current;
        let mut hi = self.max;
        while hi > lo {
            let mid = lo + ((hi - lo) / 2).max(1);
            if self.blacklist.contains(&mid) {
                hi = mid - 1;
            } else {
                return Some(mid);
            }
        }
        None
    }

    pub fn update_from_mtu(&mut self, mtu: u16) {
        let clamped = mtu.clamp(self.min, self.max);
        self.current = clamped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_with_successful_probes() {
        let mut state = PmtuState::new(1200, 1024, 1500, Duration::from_secs(1));
        let now = Instant::now();
        let probe = state.next_probe(now).expect("probe");
        state.confirm_probe(probe);
        assert!(state.current() >= probe);
    }

    #[test]
    fn blacklists_failed_sizes() {
        let mut state = PmtuState::new(1200, 1024, 1500, Duration::from_secs(1));
        let now = Instant::now();
        let probe = state.next_probe(now).expect("probe");
        state.note_blackhole(probe);
        assert!(state.next_probe(now + Duration::from_secs(2)).is_some());
    }
}

