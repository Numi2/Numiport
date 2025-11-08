// Numan Thabit 2025
// clock.rs - slot↔TAI servo
use std::time::Duration;

const MIN_SLOT_NS: u64 = 100_000_000; // 100 ms
const MAX_SLOT_NS: u64 = 1_000_000_000; // 1 s
const SMOOTHING_NUM: f64 = 0.2;

#[derive(Debug, Clone)]
pub struct SlotClock {
    epoch_slot: u64,
    epoch_time_ns: u128,
    slot_duration_ns: u64,
    last_observation: Option<(u64, u128)>,
    uncertainty_ns: u64,
}

impl SlotClock {
    pub fn new(initial_slot: u64, slot_duration: Duration, now_ns: u128) -> Self {
        let slot_duration_ns = slot_duration
            .as_nanos()
            .clamp(MIN_SLOT_NS as u128, MAX_SLOT_NS as u128) as u64;
        Self {
            epoch_slot: initial_slot,
            epoch_time_ns: now_ns,
            slot_duration_ns,
            last_observation: Some((initial_slot, now_ns)),
            uncertainty_ns: (slot_duration_ns / 100).max(1),
        }
    }

    pub fn observe(&mut self, slot: u64, time_ns: u128) {
        if let Some((last_slot, last_time)) = self.last_observation {
            if slot > last_slot && time_ns >= last_time {
                let slot_delta = slot - last_slot;
                let time_delta = time_ns - last_time;
                let measured = (time_delta / slot_delta as u128)
                    .clamp(MIN_SLOT_NS as u128, MAX_SLOT_NS as u128)
                    as u64;
                let smoothed = (self.slot_duration_ns as f64 * (1.0 - SMOOTHING_NUM)
                    + measured as f64 * SMOOTHING_NUM)
                    .round() as u64;
                self.slot_duration_ns = smoothed.clamp(MIN_SLOT_NS, MAX_SLOT_NS);
                let diff = self.slot_duration_ns.abs_diff(measured);
                self.uncertainty_ns = self
                    .uncertainty_ns
                    .max(diff / 2)
                    .min(self.slot_duration_ns / 2);
            }
        }

        self.epoch_slot = slot;
        self.epoch_time_ns = time_ns;
        self.last_observation = Some((slot, time_ns));
    }

    pub fn slot_duration(&self) -> Duration {
        Duration::from_nanos(self.slot_duration_ns)
    }

    pub fn uncertainty(&self) -> Duration {
        Duration::from_nanos(self.uncertainty_ns)
    }

    pub fn slot_start_ns(&self, slot: u64) -> u128 {
        if slot >= self.epoch_slot {
            let delta = slot - self.epoch_slot;
            self.epoch_time_ns + delta as u128 * self.slot_duration_ns as u128
        } else {
            let delta = self.epoch_slot - slot;
            self.epoch_time_ns
                .saturating_sub(delta as u128 * self.slot_duration_ns as u128)
        }
    }

    pub fn current_slot(&self, now_ns: u128) -> u64 {
        if now_ns >= self.epoch_time_ns {
            let delta = now_ns - self.epoch_time_ns;
            self.epoch_slot + (delta / self.slot_duration_ns as u128) as u64
        } else {
            let delta = self.epoch_time_ns - now_ns;
            self.epoch_slot
                .saturating_sub((delta / self.slot_duration_ns as u128) as u64)
        }
    }

    pub fn phase_within_slot(&self, now_ns: u128) -> Duration {
        let start = self.slot_start_ns(self.current_slot(now_ns));
        let phase_ns = now_ns
            .saturating_sub(start)
            .min(self.slot_duration_ns as u128);
        Duration::from_nanos(phase_ns as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoothing_adjusts_slot_duration() {
        let mut clock = SlotClock::new(10, Duration::from_millis(400), 1_000_000_000);
        clock.observe(11, 1_000_000_000 + 420_000_000);
        assert!(clock.slot_duration() >= Duration::from_millis(400));
    }

    #[test]
    fn computes_slot_start() {
        let clock = SlotClock::new(5, Duration::from_millis(400), 2_000_000_000);
        let start = clock.slot_start_ns(7);
        assert_eq!(start, 2_000_000_000 + 2 * 400_000_000);
    }
}
