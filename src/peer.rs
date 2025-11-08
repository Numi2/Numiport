#![cfg(feature = "transport-api")]

// Per-peer actor coordinating scheduling, acknowledgements, and IO.
// Numan Thabit 2025 November weekend fun
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use bytes::Bytes;
use thiserror::Error;
use tracing::{error, warn};

use crate::{
    ack::{AckDecoder, AckEncoder, ReplayOccupancy, ReplayWindow},
    api::{
        AckSet, Caps, Class, ReceivedFrame, SendMeta, Transport, TransportEvent, TransportResult,
    },
    clock::SlotClock,
    config::{Profile, ProfileName},
    crypto::{
        context::CryptoContext,
        noise::{NoiseError, NoiseHandshake, NoiseRole},
        nonce::SessionId,
        psk::PskStore,
        retry::RetryCookieManager,
        session::{SessionError, SessionManager},
    },
    metrics::Metrics,
    repair::{RepairInventory, RepairKey, RepairService},
    sched::{QueueHead, Scheduler},
    topo::TopologyCache,
    wire::{self, NumiHdr, ServiceClass, TlvBuilder, TlvType, WireError, NUMI_HDR_LEN},
};

const DEFAULT_SLOT_DURATION: Duration = Duration::from_millis(400);
const ACK_CADENCE_PACKET_LIMIT: u32 = 16;
const ACK_CADENCE_INTERVAL: Duration = Duration::from_millis(5);
const AMPLIFICATION_LIMIT: u32 = 3;
const AMPLIFICATION_INITIAL_ALLOWANCE: u64 = 1200;
const RETRY_COOKIE_TTL: Duration = Duration::from_secs(2);
const HANDSHAKE_STREAM: u32 = u32::MAX;

/// Identifier assigned to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

impl From<u64> for PeerId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
struct PendingSend {
    meta: SendMeta,
    frame: Bytes,
    wire_len: usize,
}

impl PendingSend {
    fn new(meta: SendMeta, frame: Bytes, wire_len: usize) -> Self {
        Self {
            meta,
            frame,
            wire_len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MessageKey {
    slot: u64,
    stream: u32,
    seq: u32,
}

impl MessageKey {
    fn new(meta: &SendMeta) -> Self {
        Self {
            slot: meta.slot,
            stream: meta.stream,
            seq: meta.seq,
        }
    }
}

#[derive(Debug)]
struct InflightEntry {
    class: Class,
    len: usize,
    sent_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PeerStatistics {
    pub pending_messages: usize,
    pub inflight_messages: usize,
    pub bytes_sent: u64,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub ecn_ce_marked: u64,
}

impl Default for PeerStatistics {
    fn default() -> Self {
        Self {
            pending_messages: 0,
            inflight_messages: 0,
            bytes_sent: 0,
            bytes_acked: 0,
            bytes_received: 0,
            ecn_ce_marked: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SlotMetrics {
    pub slot: u64,
    pub bytes_by_class: [u64; 4],
    pub open_for: Option<Duration>,
    pub last_send_ago: Option<Duration>,
}

#[derive(Debug)]
struct SlotState {
    slot: u64,
    bytes_by_class: [u64; 4],
    opened_at: Option<Instant>,
    last_send_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct AckCadence {
    last_emit: Instant,
    since_emit: u32,
    due: bool,
}

impl AckCadence {
    fn new(now: Instant) -> Self {
        Self {
            last_emit: now,
            since_emit: 0,
            due: true,
        }
    }

    fn note_event(&mut self) {
        self.since_emit = self.since_emit.saturating_add(1);
    }

    fn check_due(&mut self, now: Instant) {
        if self.due {
            return;
        }
        if self.since_emit >= ACK_CADENCE_PACKET_LIMIT {
            self.due = true;
            return;
        }
        if now.duration_since(self.last_emit) >= ACK_CADENCE_INTERVAL {
            self.due = true;
        }
    }

    fn on_emit(&mut self, now: Instant) {
        self.last_emit = now;
        self.since_emit = 0;
        self.due = false;
    }

    fn reset(&mut self, now: Instant) {
        self.since_emit = 0;
        self.due = false;
        self.last_emit = now;
    }
}

#[derive(Debug)]
struct AmplificationGuard {
    limit: u64,
    initial_allowance: u64,
    bytes_in: u64,
    bytes_out: u64,
    authenticated: bool,
}

impl AmplificationGuard {
    fn new(authenticated: bool) -> Self {
        Self {
            limit: AMPLIFICATION_LIMIT as u64,
            initial_allowance: AMPLIFICATION_INITIAL_ALLOWANCE,
            bytes_in: 0,
            bytes_out: 0,
            authenticated,
        }
    }

    fn on_receive(&mut self, len: usize) {
        self.bytes_in = self.bytes_in.saturating_add(len as u64);
    }

    fn can_send(&self, len: usize) -> bool {
        if self.authenticated {
            return true;
        }
        let allowance = self
            .bytes_in
            .saturating_mul(self.limit)
            .saturating_add(self.initial_allowance);
        self.bytes_out.saturating_add(len as u64) <= allowance
    }

    fn on_send(&mut self, len: usize) {
        self.bytes_out = self.bytes_out.saturating_add(len as u64);
    }

    fn mark_authenticated(&mut self) {
        self.authenticated = true;
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

#[derive(Debug)]
struct HandshakeState {
    driver: Option<NoiseHandshake>,
    role: NoiseRole,
    session_id: SessionId,
    local_id: Vec<u8>,
    remote_id: Vec<u8>,
    epoch: u64,
    outbound: VecDeque<Vec<u8>>,
    initiated: bool,
}

impl HandshakeState {
    fn new(
        handshake: NoiseHandshake,
        session_id: SessionId,
        local_id: Vec<u8>,
        remote_id: Vec<u8>,
        epoch: u64,
    ) -> Self {
        Self {
            role: handshake.role(),
            driver: Some(handshake),
            session_id,
            local_id,
            remote_id,
            epoch,
            outbound: VecDeque::new(),
            initiated: false,
        }
    }

    fn ensure_initial_message(&mut self) -> Result<(), NoiseError> {
        if self.initiated {
            return Ok(());
        }
        if self.role == NoiseRole::Initiator {
            let driver = self.driver.as_mut().ok_or(NoiseError::AlreadyCompleted)?;
            let msg = driver.write_message(&[])?;
            self.outbound.push_back(msg);
        }
        self.initiated = true;
        Ok(())
    }

    fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    fn push_front(&mut self, msg: Vec<u8>) {
        self.outbound.push_front(msg);
    }

    fn handle_incoming(&mut self, payload: &[u8]) -> Result<(), NoiseError> {
        {
            let driver = self.driver.as_mut().ok_or(NoiseError::AlreadyCompleted)?;
            driver.read_message(payload)?;
        }
        if let Some(driver) = self.driver.as_mut() {
            if !driver.is_complete() && self.role == NoiseRole::Responder {
                let msg = driver.write_message(&[])?;
                self.outbound.push_back(msg);
            }
        }
        self.initiated = true;
        Ok(())
    }

    fn try_complete(&mut self) -> Result<Option<[u8; 32]>, NoiseError> {
        let complete = match self.driver {
            Some(ref driver) => driver.is_complete(),
            None => false,
        };
        if !complete {
            return Ok(None);
        }
        let mut driver = self.driver.take().expect("handshake driver available");
        let mut session = driver.into_session()?;
        let master = session.export_master()?;
        Ok(Some(master))
    }
}

#[derive(Debug, Clone, Copy)]
struct EcnAccumulator {
    slot: Option<u64>,
    ce: u32,
    total: u32,
    summary_seen: bool,
}

impl Default for EcnAccumulator {
    fn default() -> Self {
        Self {
            slot: None,
            ce: 0,
            total: 0,
            summary_seen: false,
        }
    }
}

impl EcnAccumulator {
    fn reset(&mut self, slot: u64) {
        self.slot = Some(slot);
        self.ce = 0;
        self.total = 0;
        self.summary_seen = false;
    }
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            slot: 0,
            bytes_by_class: [0; 4],
            opened_at: None,
            last_send_at: None,
        }
    }
}

impl SlotState {
    fn ensure_slot(&mut self, slot: u64) {
        if self.slot != slot {
            self.reset(slot);
        } else if self.opened_at.is_none() {
            self.opened_at = Some(Instant::now());
        }
    }

    fn reset(&mut self, slot: u64) {
        self.slot = slot;
        self.bytes_by_class = [0; 4];
        self.opened_at = Some(Instant::now());
        self.last_send_at = None;
    }

    fn on_send(&mut self, class: Class, len: usize) {
        self.bytes_by_class[class.as_index()] += len as u64;
        self.last_send_at = Some(Instant::now());
    }

    fn metrics(&self) -> SlotMetrics {
        let now = Instant::now();
        SlotMetrics {
            slot: self.slot,
            bytes_by_class: self.bytes_by_class,
            open_for: self.opened_at.map(|ts| now.saturating_duration_since(ts)),
            last_send_ago: self
                .last_send_at
                .map(|ts| now.saturating_duration_since(ts)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot<S> {
    pub id: PeerId,
    pub profile_name: ProfileName,
    pub caps: Caps,
    pub stats: PeerStatistics,
    pub slot_metrics: SlotMetrics,
    pub oldest_inflight: Option<Duration>,
    pub transport: S,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EcnAggregate {
    pub slot: Option<u64>,
    pub ce_marks: u32,
    pub total_packets: u32,
    pub ratio: Option<f32>,
    pub summary_seen: bool,
}

impl Default for EcnAggregate {
    fn default() -> Self {
        Self {
            slot: None,
            ce_marks: 0,
            total_packets: 0,
            ratio: None,
            summary_seen: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DebugSnapshot<S> {
    pub peer: PeerSnapshot<S>,
    pub ecn: [EcnAggregate; 4],
    pub replay: ReplayOccupancy,
    pub repair: RepairInventory,
}

#[derive(Default)]
struct AckSummary {
    keys: Vec<MessageKey>,
    bytes_acked: u64,
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("ack error: {0}")]
    Ack(#[from] crate::ack::AckError),
    #[error("duplicate frame suppressed")]
    Duplicate,
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("psk store unavailable for this peer")]
    NoPskStore,
    #[error("unrecognized psk id {0}")]
    UnknownPskId(u32),
    #[error("handshake error: {0}")]
    Handshake(#[from] NoiseError),
    #[error("handshake still in progress")]
    HandshakeInProgress,
    #[error("handshake frame processed")]
    HandshakeFrame,
}

#[derive(Debug)]
pub enum CryptoBootstrap {
    Session(SessionManager),
    Psk {
        store: Arc<PskStore>,
        session_id: SessionId,
        local_id: Vec<u8>,
        remote_id: Vec<u8>,
        psk_id: u32,
        epoch: u64,
    },
    Noise {
        handshake: NoiseHandshake,
        session_id: SessionId,
        local_id: Vec<u8>,
        remote_id: Vec<u8>,
        epoch: u64,
    },
}

#[derive(Debug)]
pub struct Peer<T>
where
    T: Transport<Event = TransportEvent>,
{
    id: PeerId,
    profile_name: ProfileName,
    profile: Arc<Profile>,
    transport: T,
    crypto: Option<CryptoContext>,
    handshake: Option<HandshakeState>,
    metrics: Arc<Metrics>,
    scheduler: Scheduler,
    queues: [VecDeque<PendingSend>; 4],
    repair: RepairService,
    topology: TopologyCache<PeerId, PeerId>,
    psk_store: Option<Arc<PskStore>>,
    psk_advertise: Option<u32>,
    ack_outgoing: HashMap<(u64, u32), AckEncoder>,
    ack_cadence: HashMap<(u64, u32), AckCadence>,
    amplification: AmplificationGuard,
    retry: RetryCookieManager,
    control_tlvs: Vec<(TlvType, Vec<u8>)>,
    slot_clock: SlotClock,
    clock_origin: Instant,
    handshake_seq: u32,
    replay: ReplayWindow,
    inflight: HashMap<MessageKey, InflightEntry>,
    slot_state: SlotState,
    ecn_rx: [EcnAccumulator; 4],
    stats: PeerStatistics,
    last_event: Option<Instant>,
}

impl<T> Peer<T>
where
    T: Transport<Event = TransportEvent>,
{
    fn now_ns(&self) -> u128 {
        self.clock_origin.elapsed().as_nanos()
    }

    fn refresh_slot_timing(&mut self) {
        let slot_ns = self.slot_clock.slot_duration().as_nanos() as u64;
        let margin_ns = self.slot_clock.uncertainty().as_nanos() as u64;
        self.scheduler.set_slot_timing(slot_ns, margin_ns);
    }

    /// Creates a fully functional peer actor.
    pub fn new(
        id: PeerId,
        profile_name: ProfileName,
        profile: Arc<Profile>,
        transport: T,
        metrics: Arc<Metrics>,
        crypto: CryptoBootstrap,
    ) -> Self {
        let (maybe_session, handshake_state, psk_store, psk_advertise, initial_authenticated) =
            match crypto {
                CryptoBootstrap::Session(session) => (Some(session), None, None, None, true),
                CryptoBootstrap::Psk {
                    store,
                    session_id,
                    local_id,
                    remote_id,
                    psk_id,
                    epoch,
                } => {
                    let key = *store.resolve(psk_id).expect("psk id not found in store");
                    let session = SessionManager::new(session_id, local_id, remote_id, epoch, &key)
                        .expect("session derivation");
                    (Some(session), None, Some(store), Some(psk_id), true)
                }
                CryptoBootstrap::Noise {
                    handshake,
                    session_id,
                    local_id,
                    remote_id,
                    epoch,
                } => (
                    None,
                    Some(HandshakeState::new(
                        handshake, session_id, local_id, remote_id, epoch,
                    )),
                    None,
                    None,
                    false,
                ),
            };

        let scheduler = Scheduler::new(profile.as_ref(), DEFAULT_SLOT_DURATION, id.0);
        let clock_origin = Instant::now();
        let slot_clock = SlotClock::new(0, DEFAULT_SLOT_DURATION, 0);
        let queues = std::array::from_fn(|_| VecDeque::new());
        let repair = RepairService::default();
        let mut topology =
            TopologyCache::new(Duration::from_millis(800), Duration::from_millis(200), 2, 8);
        topology.upsert_neighbors(id, vec![id], Instant::now());
        Self {
            id,
            profile_name,
            profile,
            transport,
            crypto: maybe_session.map(CryptoContext::from_session),
            handshake: handshake_state,
            metrics,
            scheduler,
            queues,
            repair,
            topology,
            psk_store,
            psk_advertise,
            ack_outgoing: HashMap::new(),
            ack_cadence: HashMap::new(),
            amplification: AmplificationGuard::new(initial_authenticated),
            retry: RetryCookieManager::new(RETRY_COOKIE_TTL),
            control_tlvs: Vec::new(),
            slot_clock,
            clock_origin,
            handshake_seq: 0,
            replay: ReplayWindow::new(4),
            inflight: HashMap::new(),
            slot_state: SlotState::default(),
            ecn_rx: [EcnAccumulator::default(); 4],
            stats: PeerStatistics::default(),
            last_event: None,
        }
    }

    fn publish_ecn_ratio(&mut self, class: Class, ratio: f32) {
        let clamped = ratio.clamp(0.0, 1.0);
        self.scheduler.record_ecn(class, clamped);
        self.metrics.ecn_ce_ratio.observe(clamped as f64);
        if clamped >= self.profile.ecn.ce_start {
            self.topology.force_refresh(&self.id, Instant::now());
        }
    }

    fn advance_ecn_window(&mut self, class: Class, slot: u64) {
        let idx = class.as_index();
        let emit_ratio = {
            let accum = &mut self.ecn_rx[idx];
            match accum.slot {
                Some(current) if current == slot => None,
                Some(_) => {
                    let ratio = if !accum.summary_seen && accum.total > 0 {
                        Some((accum.ce as f32) / (accum.total as f32))
                    } else {
                        None
                    };
                    accum.reset(slot);
                    ratio
                }
                None => {
                    accum.reset(slot);
                    None
                }
            }
        };

        if let Some(ratio) = emit_ratio {
            self.publish_ecn_ratio(class, ratio);
        }
    }

    fn observe_ecn_mark(&mut self, class: Class, marked: bool) {
        let idx = class.as_index();
        let accum = &mut self.ecn_rx[idx];
        if accum.slot.is_none() || accum.summary_seen {
            return;
        }
        accum.total = accum.total.saturating_add(1);
        if marked {
            accum.ce = accum.ce.saturating_add(1);
        }
    }

    fn observe_ecn_summary(&mut self, class: Class, slot: u64, ratio: f32) {
        self.advance_ecn_window(class, slot);
        let idx = class.as_index();
        let already_summarized = {
            let accum = &self.ecn_rx[idx];
            accum.slot == Some(slot) && accum.summary_seen
        };
        if already_summarized {
            return;
        }

        {
            let accum = &mut self.ecn_rx[idx];
            if accum.slot.is_none() {
                accum.reset(slot);
            }
            accum.summary_seen = true;
            accum.ce = 0;
            accum.total = 0;
        }

        self.publish_ecn_ratio(class, ratio);
    }

    /// Returns the peer identifier.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// Returns the active profile configuration.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Returns the active profile name.
    pub fn profile_name(&self) -> ProfileName {
        self.profile_name
    }

    /// Exposes transport capability flags.
    pub fn caps(&self) -> Caps {
        self.transport.caps()
    }

    /// Returns the live statistics structure.
    pub fn stats(&self) -> &PeerStatistics {
        &self.stats
    }

    /// Schedules a PSK-driven rekey for the provided epoch and PSK identifier.
    pub fn schedule_psk_rekey(&mut self, epoch: u64, psk_id: u32) -> Result<(), PeerError> {
        let store = self.psk_store.as_ref().ok_or(PeerError::NoPskStore)?;
        let master = store
            .resolve(psk_id)
            .ok_or(PeerError::UnknownPskId(psk_id))?;
        let crypto = self.crypto.as_mut().ok_or(PeerError::HandshakeInProgress)?;
        crypto
            .session_mut()
            .schedule_rekey(epoch, master)
            .map_err(PeerError::Session)?;
        self.psk_advertise = Some(psk_id);
        Ok(())
    }

    /// Queues a send request. Actual transmit occurs during [`Peer::drive`].
    pub fn enqueue_send<B>(&mut self, meta: SendMeta, payload: B)
    where
        B: Into<Bytes>,
    {
        if self.crypto.is_none() && meta.stream != HANDSHAKE_STREAM && meta.stream != 3 {
            warn!(
                peer = ?self.id,
                stream = meta.stream,
                "handshake not complete; dropping payload"
            );
            return;
        }
        self.refresh_slot_timing();
        self.refresh_ack_due();
        let payload = payload.into();
        if meta.class == Class::P2 {
            let key = RepairKey {
                slot: meta.slot,
                index: meta.seq,
            };
            let now = Instant::now();
            if !self.repair.should_request(key, now) {
                return;
            }
            let slot_label = key.slot.to_string();
            self.metrics
                .repair_attempts
                .with_label_values(&[slot_label.as_str()])
                .inc();
        }

        match self.build_frame(&meta, payload) {
            Ok((frame, wire_len)) => {
                let idx = meta.class.as_index();
                self.scheduler.on_enqueue(meta.class, meta.stream, wire_len);
                self.queues[idx].push_back(PendingSend::new(meta, frame, wire_len));
                self.update_pending_stats();
            }
            Err(err) => {
                error!(peer = ?self.id, ?err, "failed to build frame");
            }
        }
    }

    /// Handles acknowledgement information from remote peers.
    pub fn handle_ack(&mut self, ack: AckSet) -> TransportResult<(), T::Error> {
        let summary = self.prepare_ack_summary(&ack);
        self.transport.ack(ack)?;
        self.apply_ack_summary(summary);
        Ok(())
    }

    /// Drives IO progress for the peer.
    pub fn drive(&mut self) -> TransportResult<Option<TransportEvent>, T::Error> {
        self.flush_pending()?;
        let polled = self.transport.poll()?;
        let event = match polled {
            Some(TransportEvent::Received(mut frame)) => match self.process_incoming(&mut frame) {
                Ok(Some(ack)) => {
                    self.handle_ack(ack)?;
                    Some(TransportEvent::Received(frame))
                }
                Ok(None) => Some(TransportEvent::Received(frame)),
                Err(PeerError::Duplicate) => Some(TransportEvent::Maintenance),
                Err(PeerError::Ack(err)) => {
                    self.metrics.nack_count.inc();
                    error!(peer = ?self.id, ?err, "ack parsing failed");
                    Some(TransportEvent::Maintenance)
                }
                Err(PeerError::Wire(err)) => {
                    match &err {
                        WireError::HeaderMac(_) => {
                            self.metrics.hdr_mac_failures.inc();
                        }
                        WireError::Aead(_) => {
                            self.metrics.aead_failures.inc();
                        }
                        _ => {}
                    }
                    error!(peer = ?self.id, ?err, "failed to process inbound frame");
                    Some(TransportEvent::Maintenance)
                }
                Err(PeerError::Session(err)) => {
                    error!(peer = ?self.id, ?err, "session error during receive");
                    Some(TransportEvent::Maintenance)
                }
                Err(PeerError::Handshake(err)) => {
                    error!(peer = ?self.id, ?err, "handshake error");
                    Some(TransportEvent::Maintenance)
                }
                Err(PeerError::HandshakeInProgress) | Err(PeerError::HandshakeFrame) => {
                    Some(TransportEvent::Maintenance)
                }
                Err(PeerError::NoPskStore) | Err(PeerError::UnknownPskId(_)) => {
                    Some(TransportEvent::Maintenance)
                }
            },
            other => other,
        };

        if event.is_some() {
            self.last_event = Some(Instant::now());
        }
        Ok(event)
    }

    /// Returns the duration since the last IO event.
    pub fn idle_for(&self) -> Option<Duration> {
        self.last_event
            .map(|t| Instant::now().saturating_duration_since(t))
    }

    /// Captures a diagnostic snapshot combining peer and transport state.
    pub fn snapshot(&self) -> TransportResult<PeerSnapshot<T::Snapshot>, T::Error> {
        let transport = self.transport.snapshot()?;
        let oldest_inflight = self
            .inflight
            .values()
            .map(|entry| entry.sent_at)
            .min()
            .map(|inst| Instant::now().saturating_duration_since(inst));

        Ok(PeerSnapshot {
            id: self.id,
            profile_name: self.profile_name,
            caps: self.transport.caps(),
            stats: self.stats.clone(),
            slot_metrics: self.slot_state.metrics(),
            oldest_inflight,
            transport,
        })
    }

    /// Captures an extended debug snapshot including ECN aggregates, replay load, and repair state.
    pub fn debug_snapshot(&self) -> TransportResult<DebugSnapshot<T::Snapshot>, T::Error> {
        let peer = self.snapshot()?;
        let ecn = self.ecn_summaries();
        let replay = self.replay.occupancy();
        let repair = self.repair.inventory();
        Ok(DebugSnapshot {
            peer,
            ecn,
            replay,
            repair,
        })
    }

    /// Convenience helper to pull a received frame out of [`TransportEvent`].
    pub fn next_frame(&mut self) -> TransportResult<Option<ReceivedFrame>, T::Error> {
        match self.drive()? {
            Some(TransportEvent::Received(frame)) => Ok(Some(frame)),
            Some(_) | None => Ok(None),
        }
    }

    fn flush_pending(&mut self) -> TransportResult<(), T::Error> {
        self.refresh_slot_timing();
        self.refresh_ack_due();
        self.drive_handshake()?;
        if self.has_ack_pending() && self.queues.iter().all(|q| q.is_empty()) {
            // Emit an ACK-only frame if there is no payload to piggyback on.
            let slot = self.min_ack_slot().unwrap_or(self.slot_state.slot);
            let meta = SendMeta {
                class: Class::P0,
                stream: 3,
                slot,
                seq: 0,
                ecn_capable: false,
            };
            let (frame, wire_len) = self
                .build_frame(&meta, Bytes::new())
                .map_err(|_e| {
                    // If building fails, just continue without sending.
                    // We avoid propagating an error to keep the drive loop resilient.
                    // No-op error mapping into transport error space by returning early below.
                })
                .ok()
                .unwrap_or((Bytes::new(), 0));
            if wire_len > 0 {
                self.queues[Class::P0.as_index()]
                    .push_back(PendingSend::new(meta, frame, wire_len));
            }
        }

        loop {
            let heads = self.queue_heads();
            let mut gated_heads = heads;
            self.filter_heads_by_amplification(&mut gated_heads);
            if gated_heads.iter().all(|head| head.is_none()) {
                break;
            }

            let min_slot = gated_heads
                .iter()
                .filter_map(|head| head.map(|h| h.slot))
                .min()
                .expect("at least one head");

            let class = match self.scheduler.select(min_slot, &gated_heads) {
                Some(class) => class,
                None => break,
            };

            let idx = class.as_index();
            let pending = match self.queues[idx].pop_front() {
                Some(pending) => pending,
                None => continue,
            };

            self.slot_state.ensure_slot(pending.meta.slot);
            self.scheduler.observe_slot(pending.meta.slot);
            self.send_one(pending)?;
        }

        self.update_pending_stats();
        Ok(())
    }

    fn send_one(&mut self, pending: PendingSend) -> TransportResult<(), T::Error> {
        let len = pending.wire_len;
        self.transport
            .send(pending.meta.clone(), pending.frame.clone())?;
        self.amplification.on_send(len);
        if pending.meta.class == Class::P2 {
            let repair_key = RepairKey {
                slot: pending.meta.slot,
                index: pending.meta.seq,
            };
            self.repair
                .record_frame(repair_key, pending.frame.clone(), Instant::now());
        }
        self.slot_state.on_send(pending.meta.class, len);
        self.scheduler
            .on_dequeue(pending.meta.class, pending.meta.stream, len);
        self.scheduler.on_send(pending.meta.class, len);
        let key = MessageKey::new(&pending.meta);
        self.inflight.insert(
            key,
            InflightEntry {
                class: pending.meta.class,
                len,
                sent_at: Instant::now(),
            },
        );
        self.stats.bytes_sent += len as u64;
        self.stats.inflight_messages = self.inflight.len();
        self.update_pending_stats();
        Ok(())
    }

    fn prepare_ack_summary(&self, ack: &AckSet) -> AckSummary {
        let mut summary = AckSummary::default();
        for range in &ack.ranges {
            let mut seq = range.start;
            loop {
                let key = MessageKey {
                    slot: ack.slot,
                    stream: ack.stream,
                    seq,
                };
                if let Some(entry) = self.inflight.get(&key) {
                    summary.bytes_acked += entry.len as u64;
                    summary.keys.push(key);
                }
                if seq == range.end {
                    break;
                }
                seq = seq.wrapping_add(1);
            }
        }
        summary
    }

    fn apply_ack_summary(&mut self, summary: AckSummary) {
        for key in summary.keys {
            if let Some(entry) = self.inflight.remove(&key) {
                if entry.class == Class::P2 {
                    let repair_key = RepairKey {
                        slot: key.slot,
                        index: key.seq,
                    };
                    self.repair.satisfy(&repair_key);
                    self.metrics.repair_success.inc();
                }
            }
        }
        self.stats.bytes_acked += summary.bytes_acked;
        self.stats.inflight_messages = self.inflight.len();
        self.metrics
            .ack_bytes_total
            .inc_by(summary.bytes_acked as u64);
        self.update_queue_metrics();
    }

    fn process_incoming(&mut self, frame: &mut ReceivedFrame) -> Result<Option<AckSet>, PeerError> {
        let packet = frame.payload.clone();
        self.amplification.on_receive(packet.len());
        let parts = crate::wire::parse_packet(packet.as_ref())?;
        if self.crypto.is_none() {
            if parts.header.stream == HANDSHAKE_STREAM {
                self.handle_handshake_payload(parts.payload)?;
                return Err(PeerError::HandshakeFrame);
            }
            return Err(PeerError::HandshakeInProgress);
        }
        let class = class_from_wire(parts.header.class);
        let crypto = self
            .crypto
            .as_mut()
            .expect("crypto context available after handshake check");

        if !self
            .replay
            .check_and_insert(parts.header.slot, parts.header.stream, parts.header.seq)
        {
            self.metrics.dup_filter_hits.inc();
            return Err(PeerError::Duplicate);
        }

        let plaintext = match crypto.open(&parts) {
            Ok(pt) => {
                if !self.amplification.is_authenticated() {
                    self.amplification.mark_authenticated();
                }
                pt
            }
            Err(err) => {
                if !self.amplification.is_authenticated()
                    && matches!(err, WireError::MissingHdrMac | WireError::HeaderMac(_))
                {
                    self.issue_retry_cookie(parts.header.slot, parts.header.stream);
                }
                return Err(PeerError::Wire(err));
            }
        };

        frame.payload = Bytes::from(plaintext);
        frame.meta.class = class;
        frame.meta.stream = parts.header.stream;
        frame.meta.slot = parts.header.slot;
        frame.meta.seq = parts.header.seq;
        frame.meta.len = frame.payload.len();
        self.advance_ecn_window(class, frame.meta.slot);
        if frame.meta.ecn_ce {
            self.stats.ecn_ce_marked = self.stats.ecn_ce_marked.saturating_add(1);
            self.topology.force_refresh(&self.id, Instant::now());
        }
        self.observe_ecn_mark(class, frame.meta.ecn_ce);

        self.stats.bytes_received += frame.payload.len() as u64;
        self.update_queue_metrics();

        self.slot_clock.observe(frame.meta.slot, self.now_ns());
        self.refresh_slot_timing();

        let parent = PeerId(frame.meta.stream as u64);
        self.topology.record_parent(parent);
        if self.topology.needs_refresh(&self.id, Instant::now()) {
            self.topology
                .upsert_neighbors(self.id, vec![parent], Instant::now());
        }

        if let Some(ecn_tlv) = parts.tlv(TlvType::EcnSummary)? {
            if ecn_tlv.value.len() >= 2 {
                let ratio = u16::from_be_bytes(ecn_tlv.value[0..2].try_into().unwrap());
                let ratio_f = (ratio as f32) / 1000.0;
                self.observe_ecn_summary(class, parts.header.slot, ratio_f);
            }
        }

        if let Some(nack_tlv) = parts.tlv(TlvType::NackList)? {
            for chunk in nack_tlv.value.chunks_exact(4) {
                let seq = u32::from_be_bytes(chunk.try_into().unwrap());
                let key = RepairKey {
                    slot: parts.header.slot,
                    index: seq,
                };
                self.metrics.nack_count.inc();
                self.metrics.repair_fail.inc();
                let now = Instant::now();
                if self.repair.should_request(key, now) {
                    let slot_label = key.slot.to_string();
                    self.metrics
                        .repair_attempts
                        .with_label_values(&[slot_label.as_str()])
                        .inc();
                }
            }
            self.topology.force_refresh(&self.id, Instant::now());
        }

        if let Some(psk_tlv) = parts.tlv(TlvType::PskId)? {
            if psk_tlv.value.len() == 4 {
                let id = u32::from_be_bytes(psk_tlv.value.try_into().unwrap());
                if let Some(store) = &self.psk_store {
                    if store.resolve(id).is_some() {
                        self.psk_advertise = Some(id);
                    }
                }
            }
        }

        if let Some(cookie_tlv) = parts.tlv(TlvType::RetryCookie)? {
            let peer_bytes = self.id.0.to_be_bytes();
            if self.retry.verify(
                &peer_bytes,
                parts.header.slot,
                parts.header.stream,
                cookie_tlv.value,
                SystemTime::now(),
            ) {
                self.metrics.retry_cookie_ok.inc();
                self.amplification.mark_authenticated();
            }
        }

        self.record_ack(parts.header.slot, parts.header.stream, parts.header.seq);

        let ack = if let Some(tlv) = parts.tlv(TlvType::AckRle)? {
            if tlv.value.len() >= 14 {
                let slot = u64::from_be_bytes(tlv.value[0..8].try_into().expect("slot bytes"));
                let stream = u32::from_be_bytes(tlv.value[8..12].try_into().expect("stream bytes"));
                let ack_len =
                    u16::from_be_bytes(tlv.value[12..14].try_into().expect("ack len")) as usize;
                if tlv.value.len() >= 14 + ack_len {
                    let ack_payload = &tlv.value[14..14 + ack_len];
                    let ranges = AckDecoder::new(ack_payload).decode()?;
                    let api_ranges = ranges
                        .into_iter()
                        .map(|r| crate::api::AckRange::new(r.start, r.end))
                        .collect();
                    Some(AckSet::new(stream, slot, api_ranges))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(ack)
    }

    fn record_ack(&mut self, slot: u64, stream: u32, seq: u32) {
        let key = (slot, stream);
        let encoder = self
            .ack_outgoing
            .entry(key)
            .or_insert_with(|| AckEncoder::new(128));
        encoder.add(seq);
        let now = Instant::now();
        let cadence = self
            .ack_cadence
            .entry(key)
            .or_insert_with(|| AckCadence::new(now));
        cadence.note_event();
        cadence.check_due(now);
    }

    fn queue_heads(&self) -> [Option<QueueHead>; 4] {
        [
            self.queues[Class::P0.as_index()]
                .front()
                .map(|p| QueueHead {
                    slot: p.meta.slot,
                    stream: p.meta.stream,
                    len: p.wire_len,
                }),
            self.queues[Class::P1.as_index()]
                .front()
                .map(|p| QueueHead {
                    slot: p.meta.slot,
                    stream: p.meta.stream,
                    len: p.wire_len,
                }),
            self.queues[Class::P2.as_index()]
                .front()
                .map(|p| QueueHead {
                    slot: p.meta.slot,
                    stream: p.meta.stream,
                    len: p.wire_len,
                }),
            self.queues[Class::P3.as_index()]
                .front()
                .map(|p| QueueHead {
                    slot: p.meta.slot,
                    stream: p.meta.stream,
                    len: p.wire_len,
                }),
        ]
    }

    fn filter_heads_by_amplification(&self, heads: &mut [Option<QueueHead>; 4]) {
        if self.amplification.is_authenticated() {
            return;
        }
        for entry in heads.iter_mut() {
            if let Some(head) = entry {
                if !self.amplification.can_send(head.len) {
                    *entry = None;
                }
            }
        }
    }

    fn update_pending_stats(&mut self) {
        self.stats.pending_messages = self.queues.iter().map(|q| q.len()).sum();
        self.update_queue_metrics();
    }

    fn update_queue_metrics(&self) {
        self.metrics
            .queue_depth_p0
            .set(self.queues[Class::P0.as_index()].len() as i64);
        self.metrics
            .queue_depth_p1
            .set(self.queues[Class::P1.as_index()].len() as i64);
        self.metrics
            .queue_depth_p2
            .set(self.queues[Class::P2.as_index()].len() as i64);
        self.metrics
            .queue_depth_p3
            .set(self.queues[Class::P3.as_index()].len() as i64);
    }

    fn ecn_summaries(&self) -> [EcnAggregate; 4] {
        let mut aggregates = [EcnAggregate::default(); 4];
        for class in Class::all() {
            let idx = class.as_index();
            let accum = self.ecn_rx[idx];
            let ratio = if accum.total > 0 {
                Some((accum.ce as f32) / (accum.total as f32))
            } else if accum.summary_seen {
                Some(0.0)
            } else {
                None
            };
            aggregates[idx] = EcnAggregate {
                slot: accum.slot,
                ce_marks: accum.ce,
                total_packets: accum.total,
                ratio,
                summary_seen: accum.summary_seen,
            };
        }
        aggregates
    }

    fn refresh_ack_due(&mut self) {
        let now = Instant::now();
        for (key, cadence) in self.ack_cadence.iter_mut() {
            if self.ack_outgoing.contains_key(key) {
                cadence.check_due(now);
            } else {
                cadence.reset(now);
            }
        }
    }

    fn drain_ack_tlvs(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut values = Vec::new();
        let mut ready = Vec::new();
        for (key, cadence) in self.ack_cadence.iter_mut() {
            if cadence.due && self.ack_outgoing.contains_key(key) {
                cadence.on_emit(now);
                ready.push(*key);
            }
        }
        for key in ready {
            if let Some(encoder) = self.ack_outgoing.remove(&key) {
                let payload = encoder.encode();
                if payload.is_empty() {
                    continue;
                }
                let (slot, stream) = key;
                let mut value = Vec::with_capacity(14 + payload.len());
                value.extend_from_slice(&slot.to_be_bytes());
                value.extend_from_slice(&stream.to_be_bytes());
                value.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                value.extend_from_slice(&payload);
                values.push(value);
            }
        }
        values
    }

    fn enqueue_control_tlv(&mut self, kind: TlvType, value: Vec<u8>) {
        self.control_tlvs.push((kind, value));
    }

    fn issue_retry_cookie(&mut self, slot: u64, stream: u32) {
        if self.amplification.is_authenticated() {
            return;
        }
        self.metrics.retry_cookie_sent.inc();
        let peer_bytes = self.id.0.to_be_bytes();
        let cookie = self
            .retry
            .encode(&peer_bytes, slot, stream, SystemTime::now());
        self.enqueue_control_tlv(TlvType::RetryCookie, cookie);
        let meta = SendMeta {
            class: Class::P0,
            stream: 3,
            slot,
            seq: 0,
            ecn_capable: false,
        };
        self.enqueue_send(meta, Bytes::new());
    }

    fn has_ack_pending(&self) -> bool {
        self.ack_outgoing.keys().any(|key| {
            self.ack_cadence
                .get(key)
                .map_or(false, |cadence| cadence.due)
        })
    }

    fn min_ack_slot(&self) -> Option<u64> {
        self.ack_outgoing
            .keys()
            .filter_map(|&(slot, stream)| {
                let key = (slot, stream);
                self.ack_cadence.get(&key).and_then(
                    |cadence| {
                        if cadence.due {
                            Some(slot)
                        } else {
                            None
                        }
                    },
                )
            })
            .min()
    }

    fn handle_handshake_payload(&mut self, payload: &[u8]) -> Result<(), PeerError> {
        let handshake = self
            .handshake
            .as_mut()
            .ok_or(PeerError::HandshakeInProgress)?;
        handshake
            .handle_incoming(payload)
            .map_err(PeerError::Handshake)?;
        self.finalize_handshake_if_complete()
    }

    fn finalize_handshake_if_complete(&mut self) -> Result<(), PeerError> {
        let maybe_master = {
            let Some(handshake) = self.handshake.as_mut() else {
                return Ok(());
            };
            handshake.try_complete().map_err(PeerError::Handshake)?
        };

        if let Some(master) = maybe_master {
            let state = self.handshake.take().expect("handshake state available");
            let manager = SessionManager::new(
                state.session_id,
                state.local_id,
                state.remote_id,
                state.epoch,
                &master,
            )
            .map_err(PeerError::Session)?;
            self.crypto = Some(CryptoContext::from_session(manager));
            self.amplification.mark_authenticated();
            self.handshake_seq = 0;
        }
        Ok(())
    }

    fn drive_handshake(&mut self) -> TransportResult<(), T::Error> {
        if let Some(handshake) = self.handshake.as_mut() {
            if let Err(err) = handshake.ensure_initial_message() {
                error!(peer = ?self.id, ?err, "failed to prepare handshake message");
                return Ok(());
            }

            while let Some(msg) = handshake.pop_outbound() {
                let msg_clone = msg.clone();
                let meta = SendMeta {
                    class: Class::P0,
                    stream: HANDSHAKE_STREAM,
                    slot: 0,
                    seq: self.handshake_seq,
                    ecn_capable: false,
                };

                let (frame, len) = match self.build_frame(&meta, Bytes::from(msg_clone)) {
                    Ok(result) => result,
                    Err(err) => {
                        error!(peer = ?self.id, ?err, "failed to build handshake frame");
                        handshake.push_front(msg);
                        break;
                    }
                };

                if !self.amplification.can_send(len) {
                    handshake.push_front(msg);
                    break;
                }

                self.transport.send(meta, frame)?;
                self.amplification.on_send(len);
                self.stats.bytes_sent += len as u64;
                self.handshake_seq = self.handshake_seq.wrapping_add(1);
            }
        }

        if let Err(err) = self.finalize_handshake_if_complete() {
            error!(peer = ?self.id, ?err, "failed to finalize handshake");
        }

        Ok(())
    }

    fn build_frame(
        &mut self,
        meta: &SendMeta,
        payload: Bytes,
    ) -> Result<(Bytes, usize), WireError> {
        let payload_len = payload.len();
        if payload_len > u16::MAX as usize {
            return Err(WireError::BufferTooShort {
                expected: payload_len,
                actual: u16::MAX as usize,
            });
        }

        let header = NumiHdr {
            version: 1,
            class: class_to_wire(meta.class),
            flags: 0,
            slot: meta.slot,
            stream: meta.stream,
            seq: meta.seq,
            fec_total: 0,
            shred_idx: 0,
            payload_len: payload_len as u16,
        };

        let mut base_tlv_builder = TlvBuilder::new();
        if let Some(psk_id) = self.psk_advertise.take() {
            let psk_bytes = psk_id.to_be_bytes();
            base_tlv_builder.push(TlvType::PskId, &psk_bytes)?;
        }
        for ack_value in self.drain_ack_tlvs() {
            base_tlv_builder.push(TlvType::AckRle, &ack_value)?;
        }
        for (kind, value) in self.control_tlvs.drain(..) {
            base_tlv_builder.push(kind, &value)?;
        }
        let base_tlvs = base_tlv_builder.finish()?;

        let mut hdr = header;

        if let Some(crypto) = self.crypto.as_mut() {
            let sealed = crypto.seal(
                meta.slot,
                meta.stream,
                meta.seq,
                &header,
                &base_tlvs,
                payload.as_ref(),
            )?;

            if payload_len == 0 && !sealed.tlv_bytes.is_empty() {
                // If we're only sending ACK TLVs without payload, set ACK_ONLY flag.
                hdr.flags |= wire::flags::ACK_ONLY;
            }

            let mut frame =
                Vec::with_capacity(NUMI_HDR_LEN + sealed.tlv_bytes.len() + sealed.ciphertext.len());
            frame.extend_from_slice(&hdr.encode()?);
            frame.extend_from_slice(&sealed.tlv_bytes);
            frame.extend_from_slice(&sealed.ciphertext);

            let wire_len = frame.len();
            Ok((Bytes::from(frame), wire_len))
        } else {
            if payload_len == 0 && !base_tlvs.is_empty() {
                hdr.flags |= wire::flags::ACK_ONLY;
            }

            let mut frame = Vec::with_capacity(NUMI_HDR_LEN + base_tlvs.len() + payload.len());
            frame.extend_from_slice(&hdr.encode()?);
            frame.extend_from_slice(&base_tlvs);
            frame.extend_from_slice(payload.as_ref());

            let wire_len = frame.len();
            Ok((Bytes::from(frame), wire_len))
        }
    }
}

fn class_to_wire(class: Class) -> ServiceClass {
    match class {
        Class::P0 => ServiceClass::P0,
        Class::P1 => ServiceClass::P1,
        Class::P2 => ServiceClass::P2,
        Class::P3 => ServiceClass::P3,
    }
}

fn class_from_wire(class: ServiceClass) -> Class {
    match class {
        ServiceClass::P0 => Class::P0,
        ServiceClass::P1 => Class::P1,
        ServiceClass::P2 => Class::P2,
        ServiceClass::P3 => Class::P3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        noise::{NoiseConfig, NoiseHandshake, NoiseRole},
        nonce::SessionId,
        session::SessionManager,
    };
    use crate::{config::Profile, repair::RepairKey};
    use bytes::Bytes;
    use rand::RngCore;
    use std::{collections::VecDeque, sync::Arc, time::Instant};
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[error("test transport error")]
    struct TestTransportError;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[derive(Debug, Clone)]
    struct TestTransport {
        caps: Caps,
        sent: Vec<(SendMeta, Bytes)>,
        inbound: VecDeque<ReceivedFrame>,
    }

    impl TestTransport {
        fn new() -> Self {
            Self {
                caps: Caps {
                    etf: false,
                    gso: false,
                    af_xdp: false,
                    io_uring: false,
                    pmtu: 1200,
                    ecn: true,
                },
                sent: Vec::new(),
                inbound: VecDeque::new(),
            }
        }

        fn push_inbound(&mut self, frame: ReceivedFrame) {
            self.inbound.push_back(frame);
        }
    }

    impl Transport for TestTransport {
        type Error = TestTransportError;
        type Event = TransportEvent;
        type Snapshot = Caps;

        fn caps(&self) -> Caps {
            self.caps
        }

        fn send(&mut self, meta: SendMeta, payload: Bytes) -> TransportResult<(), Self::Error> {
            self.sent.push((meta, payload));
            Ok(())
        }

        fn poll(&mut self) -> TransportResult<Option<Self::Event>, Self::Error> {
            if let Some(frame) = self.inbound.pop_front() {
                Ok(Some(TransportEvent::Received(frame)))
            } else {
                Ok(Some(TransportEvent::Idle))
            }
        }

        fn ack(&mut self, _ack: AckSet) -> TransportResult<(), Self::Error> {
            Ok(())
        }

        fn snapshot(&self) -> TransportResult<Self::Snapshot, Self::Error> {
            Ok(self.caps)
        }
    }

    fn make_peer() -> Peer<TestTransport> {
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());
        let session_id = SessionId::random();
        let master = [0u8; 32];
        let session =
            SessionManager::new(session_id, b"local", b"remote", 0, &master).expect("session");
        Peer::new(
            PeerId(1),
            ProfileName::IntraDc,
            profile,
            TestTransport::new(),
            metrics,
            CryptoBootstrap::Session(session),
        )
    }

    #[test]
    fn debug_snapshot_reports_default_state() {
        let peer = make_peer();
        let snapshot = peer.debug_snapshot().expect("snapshot");
        assert_eq!(snapshot.peer.id, PeerId(1));
        assert_eq!(snapshot.peer.transport.pmtu, snapshot.peer.caps.pmtu);
        assert_eq!(snapshot.repair.recent_entries, 0);
        assert_eq!(snapshot.replay.slots, 0);
        assert!(snapshot.ecn.iter().all(|agg| agg.ratio.is_none()));
        assert!(snapshot.ecn.iter().all(|agg| agg.slot.is_none()));
    }

    #[test]
    fn debug_snapshot_reflects_repair_inventory() {
        let mut peer = make_peer();
        let key = RepairKey { slot: 10, index: 5 };
        peer.repair
            .record_frame(key, Bytes::from_static(b"repair-data"), Instant::now());
        let inventory = peer.repair.inventory();
        assert!(inventory.recent_entries > 0 || inventory.deep_entries > 0);
        let snapshot = peer.debug_snapshot().expect("snapshot");
        assert_eq!(snapshot.repair.recent_entries, inventory.recent_entries);
        assert_eq!(snapshot.repair.deep_entries, inventory.deep_entries);
        assert_eq!(snapshot.repair.deep_slots, inventory.deep_slots);
        assert!(snapshot.repair.recent_entries + snapshot.repair.deep_entries > 0);
    }

    #[test]
    fn handshake_completes_between_peers() {
        let session_id = SessionId::random();
        let epoch = 0;
        let initiator_static = random_key();
        let responder_static = random_key();
        let psk = random_key();

        let initiator_handshake = NoiseHandshake::new(
            NoiseRole::Initiator,
            NoiseConfig::new(initiator_static, Some(responder_static), psk),
        )
        .expect("initiator handshake");
        let responder_handshake = NoiseHandshake::new(
            NoiseRole::Responder,
            NoiseConfig::new(responder_static, None, psk),
        )
        .expect("responder handshake");

        let metrics_a = Arc::new(Metrics::new().expect("metrics"));
        let metrics_b = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());

        let mut initiator = Peer::new(
            PeerId(1),
            ProfileName::IntraDc,
            profile.clone(),
            TestTransport::new(),
            metrics_a,
            CryptoBootstrap::Noise {
                handshake: initiator_handshake,
                session_id,
                local_id: b"validator-a".to_vec(),
                remote_id: b"validator-b".to_vec(),
                epoch,
            },
        );

        let mut responder = Peer::new(
            PeerId(2),
            ProfileName::IntraDc,
            profile,
            TestTransport::new(),
            metrics_b,
            CryptoBootstrap::Noise {
                handshake: responder_handshake,
                session_id,
                local_id: b"validator-a".to_vec(),
                remote_id: b"validator-b".to_vec(),
                epoch,
            },
        );

        // Initiator sends first handshake message.
        initiator.drive().expect("initiator drive");
        assert_eq!(initiator.transport.sent.len(), 1);
        let (meta1, frame1) = initiator.transport.sent.remove(0);
        responder.transport.push_inbound(ReceivedFrame {
            meta: RecvMeta {
                class: meta1.class,
                stream: meta1.stream,
                slot: meta1.slot,
                seq: meta1.seq,
                len: frame1.len(),
                ecn_ce: false,
                received_at: Instant::now(),
            },
            payload: frame1.clone(),
        });

        // Responder processes handshake and replies.
        responder.drive().expect("responder drive");
        assert!(
            !responder.transport.sent.is_empty(),
            "responder should emit handshake response"
        );
        let (meta2, frame2) = responder.transport.sent.remove(0);
        initiator.transport.push_inbound(ReceivedFrame {
            meta: RecvMeta {
                class: meta2.class,
                stream: meta2.stream,
                slot: meta2.slot,
                seq: meta2.seq,
                len: frame2.len(),
                ecn_ce: false,
                received_at: Instant::now(),
            },
            payload: frame2.clone(),
        });

        // Initiator processes response completing the handshake.
        initiator.drive().expect("initiator drive response");

        // Responder finalizes handshake after sending response.
        responder.drive().expect("responder finalize");

        assert!(initiator.handshake.is_none());
        assert!(responder.handshake.is_none());
        assert!(initiator.crypto.is_some());
        assert!(responder.crypto.is_some());

        // Clear any leftover sent frames before transmitting real data.
        initiator.transport.sent.clear();
        responder.transport.sent.clear();

        // Send a payload from initiator to responder to ensure encryption works.
        let payload = Bytes::from_static(b"hello numiport");
        let meta = SendMeta::new(Class::P1, 0, 1, 0);
        initiator.enqueue_send(meta, payload.clone());
        initiator.drive().expect("initiator send payload");
        assert_eq!(initiator.transport.sent.len(), 1);
        let (data_meta, data_frame) = initiator.transport.sent.remove(0);
        responder.transport.push_inbound(ReceivedFrame {
            meta: RecvMeta {
                class: data_meta.class,
                stream: data_meta.stream,
                slot: data_meta.slot,
                seq: data_meta.seq,
                len: data_frame.len(),
                ecn_ce: false,
                received_at: Instant::now(),
            },
            payload: data_frame.clone(),
        });

        match responder.drive().expect("responder receive payload") {
            Some(TransportEvent::Received(frame)) => {
                assert_eq!(frame.payload, payload);
            }
            other => panic!("unexpected event from responder: {:?}", other),
        }
    }
}
