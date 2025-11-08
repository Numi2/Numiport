// Numan Thabit 2025
// sched/credits.rs - leaky-bucket credits, ECN scaling

use std::fmt;

use crate::config::EcnScaler;

/// Fixed-point scale factor with six decimal places of precision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Scale(u32);

impl Scale {
    const ONE: u32 = 1_000_000;

    /// Represents a multiplicative factor of `1.0` (no scaling).
    pub const fn unity() -> Self {
        Self(Self::ONE)
    }

    /// Creates a scale from a floating point number, clamping to a sensible range.
    pub fn from_f32(value: f32) -> Self {
        let clamped = value.clamp(0.05, 5.0);
        let scaled = (clamped * Self::ONE as f32).round() as u32;
        Self(scaled.max(1))
    }

    /// Multiplies the scale by another scale, returning the saturated result.
    pub fn saturating_mul(self, other: Self) -> Self {
        let product = (self.0 as u64) * (other.0 as u64);
        let value = (product / Self::ONE as u64).min(u32::MAX as u64);
        Self(value as u32)
    }

    /// Converts the scale into a rational `(numerator, denominator)` pair.
    pub fn as_ratio(self) -> (u32, u32) {
        (self.0, Self::ONE)
    }

    /// Applies the scale to an integer quantity, returning a rounded result.
    pub fn apply_u64(self, value: u64) -> u64 {
        ((value as u128 * self.0 as u128) / Self::ONE as u128) as u64
    }
}

impl Default for Scale {
    fn default() -> Self {
        Self::unity()
    }
}

impl fmt::Display for Scale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.0 as f64 / Self::ONE as f64)
    }
}

/// Encapsulates the leaky-bucket credit state for a traffic class.
#[derive(Debug, Clone)]
pub struct CreditTracker {
    slot_ns: u64,
    budget_per_slot: u64,
    floor_per_slot: u64,
    burst_cap: u64,
    scale: Scale,
    available: u128,
    remainder: u128,
    last_ns: Option<u128>,
}

impl CreditTracker {
    /// Creates a new tracker for the provided slot duration and budget configuration.
    pub fn new(slot_ns: u64, budget_per_slot: u64, floor_per_slot: u64, burst_cap: u64) -> Self {
        let mut tracker = Self {
            slot_ns: slot_ns.max(1),
            budget_per_slot,
            floor_per_slot,
            burst_cap,
            scale: Scale::unity(),
            available: 0,
            remainder: 0,
            last_ns: None,
        };
        tracker.reset_window();
        tracker
    }

    /// Resets slot-derived parameters while carrying over remaining credits.
    pub fn reconfigure(
        &mut self,
        slot_ns: u64,
        budget_per_slot: u64,
        floor_per_slot: u64,
        burst_cap: u64,
    ) {
        self.settle(self.last_ns.unwrap_or_default());
        self.slot_ns = slot_ns.max(1);
        self.budget_per_slot = budget_per_slot;
        self.floor_per_slot = floor_per_slot;
        self.burst_cap = burst_cap;
        self.enforce_capacity();
    }

    /// Applies a new ECN scale factor. Outstanding credits are scaled in place.
    pub fn set_scale(&mut self, scale: Scale) {
        self.scale = scale;
        self.enforce_capacity();
    }

    /// Returns the currently available credits (scaled) in bytes.
    pub fn available(&self) -> u64 {
        self.available.min(self.capacity()) as u64
    }

    /// Returns the slot-level floor for this class after scaling.
    pub fn floor(&self) -> u64 {
        self.scale.apply_u64(self.floor_per_slot)
    }

    /// Accounts for elapsed time and replenishes credits.
    pub fn settle(&mut self, now_ns: u128) {
        if let Some(last) = self.last_ns {
            if now_ns > last {
                let elapsed = now_ns - last;
                let scaled_budget = self.scaled_budget();
                let numerator = (scaled_budget as u128) * elapsed + self.remainder;
                let slot_ns = self.slot_ns as u128;
                let delta = numerator / slot_ns;
                self.remainder = numerator % slot_ns;
                self.available = (self.available + delta).min(self.capacity());
            }
        }
        self.last_ns = Some(now_ns);
    }

    /// Attempts to consume the requested number of bytes. Returns `true` when successful.
    pub fn try_consume(&mut self, amount: u64, now_ns: u128) -> bool {
        self.settle(now_ns);
        let amount_u128 = amount as u128;
        if self.available < amount_u128 {
            return false;
        }
        self.available -= amount_u128;
        true
    }

    /// Injects bytes back into the bucket (used when a send fails and is retried).
    pub fn refund(&mut self, amount: u64) {
        let amount = amount as u128;
        self.available = (self.available + amount).min(self.capacity());
    }

    /// Called at the start of every slot to add the slot budget instantaneously before pacing.
    pub fn reset_window(&mut self) {
        self.available = self.capacity();
        self.remainder = 0;
    }

    pub fn start_slot(&mut self, now_ns: u128) {
        self.available = self.capacity();
        self.remainder = 0;
        self.last_ns = Some(now_ns);
    }

    fn scaled_budget(&self) -> u64 {
        self.scale.apply_u64(self.budget_per_slot)
    }

    fn capacity(&self) -> u128 {
        let cap = self
            .scale
            .apply_u64(self.burst_cap.max(self.budget_per_slot));
        cap as u128
    }

    fn enforce_capacity(&mut self) {
        self.available = self.available.min(self.capacity());
    }
}

/// ECN-driven scaler that computes deterministic multiplicative adjustments per slot.
#[derive(Debug, Clone)]
pub struct EcnCreditScaler {
    config: EcnScaler,
    current: Scale,
    stable_slots: u16,
}

impl EcnCreditScaler {
    pub fn new(config: EcnScaler) -> Self {
        Self {
            config,
            current: Scale::unity(),
            stable_slots: 0,
        }
    }

    pub fn scale(&self) -> Scale {
        self.current
    }

    /// Updates the scaler using the observed CE ratio in the previous slot.
    pub fn update(&mut self, ce_ratio: f32) -> Scale {
        let next = if ce_ratio >= self.config.ce_stop {
            Scale::from_f32(self.config.min_scale)
        } else if ce_ratio >= self.config.ce_start {
            // Linear interpolation between min_scale and 1.0.
            let span = self.config.ce_stop - self.config.ce_start;
            let pos = (ce_ratio - self.config.ce_start) / span.max(f32::EPSILON);
            let factor = 1.0 - pos * (1.0 - self.config.min_scale);
            Scale::from_f32(factor)
        } else {
            self.stable_slots += 1;
            if self.stable_slots >= 16 {
                self.stable_slots = 0;
                Scale::from_f32((self.config.max_scale).min(1.02))
            } else {
                self.current
            }
        };

        if next.0 > self.current.0 {
            // Bound step-up rate to avoid oscillations.
            let bounded = ((self.current.0 as u64 * 102) / 100).min(next.0 as u64);
            self.current = Scale(bounded as u32);
        } else {
            self.current = next;
            self.stable_slots = 0;
        }
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecn_scaler() -> EcnScaler {
        EcnScaler {
            ce_start: 0.01,
            ce_stop: 0.03,
            min_scale: 0.5,
            max_scale: 1.2,
        }
    }

    #[test]
    fn credits_replenish_over_time() {
        let mut credits = CreditTracker::new(100_000, 10_000, 1_000, 12_000);
        credits.set_scale(Scale::unity());
        credits.reset_window();

        assert!(credits.try_consume(8_000, 0));
        assert_eq!(credits.available(), 4_000);

        // After half a slot, roughly half the budget should replenish.
        credits.settle(50_000);
        assert!(credits.available() >= 8_000);
    }

    #[test]
    fn ecn_scaler_reduces_on_marks() {
        let mut scaler = EcnCreditScaler::new(ecn_scaler());
        let original = scaler.scale();
        let scaled = scaler.update(0.05);
        assert!(scaled.0 < original.0);
    }

    #[test]
    fn ecn_scaler_increases_when_stable() {
        let mut scaler = EcnCreditScaler::new(ecn_scaler());
        let original = scaler.scale();
        for _ in 0..20 {
            scaler.update(0.0);
        }
        assert!(scaler.scale().0 >= original.0);
    }
}
