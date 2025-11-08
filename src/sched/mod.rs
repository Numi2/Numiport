#![cfg(feature = "transport-api")]

// Numan Thabit 2025 November
// sched/mod.rs - scheduler module
use std::{
    hash::Hash,
    time::{Duration, Instant},
};

use ahash::AHashMap;

pub mod credits;
pub mod drr;
pub mod edf;
pub mod phase;

use self::{
    credits::{CreditTracker, EcnCreditScaler},
    phase::PhaseDesync,
};
use crate::{api::Class, config::Profile};

const P0_BURST_LIMIT: u32 = 8;
const P1_BURST_LIMIT: u32 = 8;

#[derive(Debug, Clone, Copy)]
pub struct QueueHead {
    pub slot: u64,
    pub stream: u32,
    pub len: usize,
}

#[derive(Debug)]
pub struct Scheduler {
    credits: [CreditTracker; 4],
    floors: [u64; 4],
    floor_remaining: [u64; 4],
    ecn_scalers: [EcnCreditScaler; 4],
    backlog: [AHashMap<u32, u64>; 4],
    drr_p1: drr::DeficitRoundRobin<u32>,
    drr_p2: drr::DeficitRoundRobin<u32>,
    budgets: [u64; 4],
    burst_caps: [u64; 4],
    slot_ns: u64,
    slot_anchor_slot: u64,
    slot_anchor_time: u128,
    current_slot: u64,
    slot_margin_ns: u64,
    burst_counters: [u32; 4],
    last_class: Option<Class>,
    phase_offset_ns: u64,
    start: Instant,
}

impl Scheduler {
    pub fn new<H: Hash>(profile: &Profile, slot_duration: Duration, peer_key: H) -> Self {
        let slot_ns = slot_duration.as_nanos() as u64;
        let budgets = [
            profile.budgets.p0,
            profile.budgets.p1,
            profile.budgets.p2,
            profile.budgets.p3,
        ];
        let floors = [0, profile.floors.p1, profile.floors.p2, 0];
        let burst_caps = [
            profile.burst_caps.p0,
            profile.burst_caps.p1,
            profile.burst_caps.p2,
            profile.burst_caps.p3,
        ];

        let credits = std::array::from_fn(|idx| {
            CreditTracker::new(slot_ns, budgets[idx], floors[idx], burst_caps[idx])
        });
        let ecn_scalers = std::array::from_fn(|_| EcnCreditScaler::new(profile.ecn.clone()));
        let phase = PhaseDesync::new(8);
        let phase_offset = phase.phase_for_peer(&peer_key, slot_duration).as_nanos() as u64;

        let backlog = std::array::from_fn(|_| AHashMap::default());
        let drr_p1 = drr::DeficitRoundRobin::new(64 * 1024);
        let drr_p2 = drr::DeficitRoundRobin::new(64 * 1024);

        Self {
            credits,
            floors,
            floor_remaining: floors,
            ecn_scalers,
            backlog,
            drr_p1,
            drr_p2,
            budgets,
            burst_caps,
            slot_ns,
            slot_anchor_slot: 0,
            slot_anchor_time: 0,
            slot_margin_ns: slot_ns / 16,
            current_slot: 0,
            burst_counters: [0; 4],
            last_class: None,
            phase_offset_ns: phase_offset,
            start: Instant::now(),
        }
    }

    pub fn observe_slot(&mut self, slot: u64) {
        if slot > self.current_slot {
            self.current_slot = slot;
            let now = self.now_ns();
            for credit in &mut self.credits {
                credit.start_slot(now);
            }
            self.floor_remaining = self.floors;
            self.slot_anchor_slot = slot;
            self.slot_anchor_time = now;
            self.reset_burst();
        } else if self.slot_anchor_time == 0 {
            self.slot_anchor_slot = slot;
            self.slot_anchor_time = self.now_ns();
        }
    }

    pub fn select(&mut self, slot: u64, heads: &[Option<QueueHead>; 4]) -> Option<Class> {
        self.observe_slot(slot);
        let now = self.now_ns();

        if !self.phase_ready(slot, now) {
            return None;
        }

        let p0_head = heads[Class::P0.as_index()].filter(|head| head.slot == slot);
        if let Some(head) = p0_head {
            if self.burst_allows(Class::P0, slot, heads) && self.consume(Class::P0, head.len, now) {
                return Some(Class::P0);
            }
        }

        let p1_head = heads[Class::P1.as_index()].filter(|head| head.slot == slot);
        let p2_head = heads[Class::P2.as_index()].filter(|head| head.slot == slot);
        let p3_head = heads[Class::P3.as_index()].filter(|head| head.slot == slot);

        let mut order: Vec<Class> = Vec::with_capacity(3);
        let mut p2_floor_enforced = false;

        if let Some(_) = p2_head {
            if self.floor_remaining[Class::P2.as_index()] > 0 {
                order.push(Class::P2);
                p2_floor_enforced = true;
            }
        }

        match (p1_head, p2_head) {
            (Some(h1), Some(h2)) => {
                if !p2_floor_enforced {
                    if self.deadline_for(Class::P2, h2.slot)
                        <= self.deadline_for(Class::P1, h1.slot)
                    {
                        order.push(Class::P2);
                        order.push(Class::P1);
                    } else {
                        order.push(Class::P1);
                        order.push(Class::P2);
                    }
                } else {
                    order.push(Class::P1);
                }
            }
            (Some(_), None) => order.push(Class::P1),
            (None, Some(_)) => {
                if !p2_floor_enforced {
                    order.push(Class::P2);
                }
            }
            _ => {}
        }

        if p3_head.is_some() {
            order.push(Class::P3);
        }

        for class in order {
            match class {
                Class::P1 => {
                    if let Some(head) = p1_head {
                        if self.burst_allows(Class::P1, slot, heads)
                            && self.consume_with_drr(Class::P1, head.stream, head.len, now)
                        {
                            return Some(Class::P1);
                        }
                    }
                }
                Class::P2 => {
                    if let Some(head) = p2_head {
                        if self.consume_with_drr(Class::P2, head.stream, head.len, now) {
                            return Some(Class::P2);
                        }
                    }
                }
                Class::P3 => {
                    if let Some(head) = p3_head {
                        if self.consume(Class::P3, head.len, now) {
                            return Some(Class::P3);
                        }
                    }
                }
                Class::P0 => {}
            }
        }

        None
    }

    pub fn on_send(&mut self, class: Class, bytes: usize) {
        let idx = class.as_index();
        let consumed = bytes as u64;
        if self.floor_remaining[idx] > 0 {
            self.floor_remaining[idx] = self.floor_remaining[idx].saturating_sub(consumed);
        }
        self.update_burst(class);
    }

    pub fn on_enqueue(&mut self, class: Class, stream: u32, bytes: usize) {
        if !matches!(class, Class::P1 | Class::P2) {
            return;
        }
        let idx = class.as_index();
        let entry = self.backlog[idx].entry(stream).or_insert(0);
        *entry = entry.saturating_add(bytes as u64);
        match class {
            Class::P1 => self.drr_p1.set_backlog(&stream, *entry),
            Class::P2 => self.drr_p2.set_backlog(&stream, *entry),
            _ => {}
        }
    }

    pub fn on_dequeue(&mut self, class: Class, stream: u32, bytes: usize) {
        if !matches!(class, Class::P1 | Class::P2) {
            return;
        }
        let idx = class.as_index();
        if let Some(entry) = self.backlog[idx].get_mut(&stream) {
            *entry = entry.saturating_sub(bytes as u64);
            match class {
                Class::P1 => self.drr_p1.set_backlog(&stream, *entry),
                Class::P2 => self.drr_p2.set_backlog(&stream, *entry),
                _ => {}
            }
            if *entry == 0 {
                self.backlog[idx].remove(&stream);
            }
        }
    }

    pub fn record_ecn(&mut self, class: Class, ce_ratio: f32) {
        let idx = class.as_index();
        let scale = self.ecn_scalers[idx].update(ce_ratio);
        self.credits[idx].set_scale(scale);
    }

    pub fn now_ns(&self) -> u128 {
        self.start.elapsed().as_nanos()
    }

    pub fn phase_offset_ns(&self) -> u64 {
        self.phase_offset_ns
    }

    pub fn set_slot_timing(&mut self, slot_ns: u64, margin_ns: u64) {
        let slot_ns = slot_ns.max(1);
        if slot_ns != self.slot_ns {
            self.slot_ns = slot_ns;
            for idx in 0..self.credits.len() {
                self.credits[idx].reconfigure(
                    slot_ns,
                    self.budgets[idx],
                    self.floors[idx],
                    self.burst_caps[idx],
                );
            }
            self.slot_anchor_time = self.now_ns();
            self.slot_anchor_slot = self.current_slot;
        }
        self.slot_margin_ns = margin_ns.min(slot_ns);
    }

    fn slot_start_ns(&self, slot: u64) -> u128 {
        if slot >= self.slot_anchor_slot {
            self.slot_anchor_time
                .saturating_add((slot - self.slot_anchor_slot) as u128 * self.slot_ns as u128)
        } else {
            self.slot_anchor_time
                .saturating_sub((self.slot_anchor_slot - slot) as u128 * self.slot_ns as u128)
        }
    }

    fn deadline_for(&self, class: Class, slot: u64) -> u128 {
        self.slot_start_ns(slot)
            .saturating_add(self.class_margin_ns(class))
    }

    fn class_margin_ns(&self, class: Class) -> u128 {
        let guard = self.slot_margin_ns.min(self.slot_ns) as u128;
        let base = match class {
            Class::P0 => 0,
            Class::P1 => (self.slot_ns as u128) / 4,
            Class::P2 => (self.slot_ns as u128) / 2,
            Class::P3 => (self.slot_ns as u128) * 3 / 4,
        };
        base.saturating_sub(guard)
    }

    fn phase_ready(&self, slot: u64, now: u128) -> bool {
        let phase_start = self
            .slot_start_ns(slot)
            .saturating_add(self.phase_offset_ns as u128);
        now >= phase_start
    }

    fn burst_allows(&self, class: Class, slot: u64, heads: &[Option<QueueHead>; 4]) -> bool {
        match class {
            Class::P0 => {
                let count = self.burst_counters[Class::P0.as_index()];
                if count < P0_BURST_LIMIT {
                    return true;
                }
                let other_ready = heads.iter().enumerate().any(|(idx, head)| {
                    idx != Class::P0.as_index() && head.map_or(false, |h| h.slot == slot)
                });
                !other_ready
            }
            Class::P1 => {
                let count = self.burst_counters[Class::P1.as_index()];
                if count < P1_BURST_LIMIT {
                    return true;
                }
                let p2_ready = heads[Class::P2.as_index()].map_or(false, |h| h.slot == slot);
                !p2_ready
            }
            _ => true,
        }
    }

    fn reset_burst_counter(&mut self, class: Class) {
        let idx = class.as_index();
        self.burst_counters[idx] = 0;
    }

    fn reset_burst(&mut self) {
        self.reset_burst_counter(Class::P0);
        self.reset_burst_counter(Class::P1);
        self.last_class = None;
    }

    fn update_burst(&mut self, class: Class) {
        match class {
            Class::P0 => {
                if self.last_class == Some(Class::P0) {
                    let idx = Class::P0.as_index();
                    self.burst_counters[idx] = self.burst_counters[idx].saturating_add(1);
                } else {
                    self.reset_burst_counter(Class::P1);
                    self.burst_counters[Class::P0.as_index()] = 1;
                }
                self.last_class = Some(Class::P0);
            }
            Class::P1 => {
                if self.last_class == Some(Class::P1) {
                    let idx = Class::P1.as_index();
                    self.burst_counters[idx] = self.burst_counters[idx].saturating_add(1);
                } else {
                    self.reset_burst_counter(Class::P0);
                    self.burst_counters[Class::P1.as_index()] = 1;
                }
                self.last_class = Some(Class::P1);
            }
            _ => {
                self.reset_burst_counter(Class::P0);
                self.reset_burst_counter(Class::P1);
                self.last_class = Some(class);
            }
        }
    }

    fn consume(&mut self, class: Class, len: usize, now: u128) -> bool {
        self.credits[class.as_index()].try_consume(len as u64, now)
    }

    fn consume_with_drr(&mut self, class: Class, stream: u32, len: usize, now: u128) -> bool {
        if !self.consume(class, len, now) {
            return false;
        }

        let selection = match class {
            Class::P1 => self.drr_p1.pop_next(len as u64),
            Class::P2 => self.drr_p2.pop_next(len as u64),
            _ => Some(stream),
        };

        match selection {
            Some(selected) if selected == stream => true,
            Some(selected) => {
                if let Some(backlog) = self.backlog[class.as_index()].get(&selected) {
                    match class {
                        Class::P1 => self.drr_p1.set_backlog(&selected, *backlog),
                        Class::P2 => self.drr_p2.set_backlog(&selected, *backlog),
                        _ => {}
                    }
                }
                self.credits[class.as_index()].refund(len as u64);
                false
            }
            None => {
                self.credits[class.as_index()].refund(len as u64);
                false
            }
        }
    }
}
