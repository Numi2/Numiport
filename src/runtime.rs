#![cfg(feature = "transport-api")]

//! Tokio-based runtime scaffolding for driving `Peer` actors.
//!
//! This module provides a small executor wrapper around [`Peer`](crate::Peer) that repeatedly
//! invokes [`Peer::drive`](crate::Peer::drive) on a fixed interval and surfaces transport events
//! through an asynchronous channel. The README describes each remote validator as being managed by
//! its own actor task; `spawn_peer` is the entry-point for launching that task.

use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    sync::{
        mpsc::{self, error::TrySendError, Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, warn};

use crate::{
    api::{AckSet, SendMeta, TransportEvent, TransportResult},
    peer::{DebugSnapshot, Peer, PeerId, PeerSnapshot},
};

/// Configuration parameters controlling how a peer actor is driven by the runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Interval used to call [`Peer::drive`](crate::peer::Peer::drive).
    pub tick: Duration,
    /// Capacity of the command channel used between the handle and actor task.
    pub command_buffer: usize,
    /// Capacity of the event channel surfaced to the caller.
    pub event_buffer: usize,
    /// Duration the peer must remain idle before an [`RuntimeEvent::Idle`] notification is emitted.
    pub idle_after: Duration,
    /// Minimum gap between successive idle notifications.
    pub idle_interval: Duration,
    /// Number of consecutive transport errors tolerated before the runtime terminates the actor.
    pub max_error_burst: usize,
    /// Grace period allowed for the actor task to stop during [`PeerHandle::shutdown`].
    pub shutdown_grace: Duration,
}

impl RuntimeConfig {
    /// Creates a new configuration with the provided drive interval and default values for the
    /// remaining parameters.
    pub fn new(tick: Duration) -> Self {
        Self {
            tick,
            ..Self::default()
        }
    }

    /// Sets the command channel capacity.
    pub fn with_command_buffer(mut self, capacity: usize) -> Self {
        self.command_buffer = capacity.max(1);
        self
    }

    /// Sets the event channel capacity.
    pub fn with_event_buffer(mut self, capacity: usize) -> Self {
        self.event_buffer = capacity.max(1);
        self
    }

    /// Sets the idle notification thresholds.
    pub fn with_idle_threshold(mut self, idle_after: Duration, idle_interval: Duration) -> Self {
        self.idle_after = idle_after;
        self.idle_interval = idle_interval;
        self
    }

    /// Sets the maximum tolerated burst of consecutive transport errors.
    pub fn with_max_error_burst(mut self, burst: usize) -> Self {
        self.max_error_burst = burst;
        self
    }

    /// Sets the grace period used when shutting down the actor task.
    pub fn with_shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = grace;
        self
    }

    fn normalize(&mut self) {
        if self.command_buffer == 0 {
            self.command_buffer = 1;
        }
        if self.event_buffer == 0 {
            self.event_buffer = 1;
        }
        if self.idle_interval < self.idle_after {
            self.idle_interval = self.idle_after;
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tick: Duration::from_millis(5),
            command_buffer: 512,
            event_buffer: 1024,
            idle_after: Duration::from_millis(100),
            idle_interval: Duration::from_millis(500),
            max_error_burst: 4,
            shutdown_grace: Duration::from_secs(1),
        }
    }
}

/// Reason why a peer actor task stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStopReason {
    /// The actor shut down after receiving an explicit [`PeerCommand::Shutdown`].
    Shutdown,
    /// The handle dropped the command channel without sending a shutdown request.
    CommandChannelClosed,
    /// The event channel was dropped by the consumer and the actor stopped emitting events.
    EventChannelClosed,
    /// The runtime aborted the actor after a burst of transport errors.
    Fatal,
}

/// Events emitted by a running peer task.
#[derive(Debug)]
pub enum RuntimeEvent<TE> {
    /// A transport-level event produced by [`Peer::drive`](crate::Peer::drive).
    Transport(TransportEvent),
    /// The underlying transport produced an error during polling.
    TransportError(TE),
    /// The peer remained idle for at least [`RuntimeConfig::idle_after`].
    Idle(Duration),
    /// The runtime terminated the actor after repeated transport errors.
    Fatal {
        /// Number of back-to-back errors encountered before termination.
        consecutive_errors: usize,
    },
    /// The actor task finished execution.
    Stopped(PeerStopReason),
}

/// Handle used to interact with a spawned peer actor.
#[derive(Debug)]
pub struct PeerHandle<T>
where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    id: PeerId,
    commands: Sender<PeerCommand<T>>,
    join: JoinHandle<()>,
    config: Arc<RuntimeConfig>,
    _marker: PhantomData<T>,
}

impl<T> PeerHandle<T>
where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    /// Returns the peer identifier associated with the actor.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// Returns a reference to the runtime configuration associated with the actor.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Queues a payload for transmission.
    pub fn send<B>(&self, meta: SendMeta, payload: B) -> Result<(), PeerHandleError>
    where
        B: Into<Bytes>,
    {
        let payload = payload.into();
        self.commands
            .try_send(PeerCommand::Send(meta, payload))
            .map_err(|err| match err {
                TrySendError::Closed(_) => PeerHandleError::ChannelClosed,
                TrySendError::Full(_) => PeerHandleError::CommandQueueFull,
            })
    }

    /// Submits acknowledgement information to the peer.
    pub fn ack(&self, ack: AckSet) -> Result<(), PeerHandleError> {
        self.commands
            .try_send(PeerCommand::Ack(ack))
            .map_err(|err| match err {
                TrySendError::Closed(_) => PeerHandleError::ChannelClosed,
                TrySendError::Full(_) => PeerHandleError::CommandQueueFull,
            })
    }

    /// Requests a snapshot and awaits the result.
    pub async fn snapshot(
        &self,
    ) -> Result<TransportResult<PeerSnapshot<T::Snapshot>, T::Error>, PeerHandleError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::Snapshot(tx))
            .await
            .map_err(|_| PeerHandleError::ChannelClosed)?;
        rx.await.map_err(|_| PeerHandleError::ActorStopped)
    }

    /// Requests a debug snapshot and awaits the result.
    pub async fn debug_snapshot(
        &self,
    ) -> Result<TransportResult<DebugSnapshot<T::Snapshot>, T::Error>, PeerHandleError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::DebugSnapshot(tx))
            .await
            .map_err(|_| PeerHandleError::ChannelClosed)?;
        rx.await.map_err(|_| PeerHandleError::ActorStopped)
    }

    /// Signals the peer actor to terminate and waits for the join handle.
    pub async fn shutdown(self) -> Result<(), PeerHandleError> {
        let PeerHandle {
            commands,
            join,
            config,
            ..
        } = self;

        commands
            .send(PeerCommand::Shutdown)
            .await
            .map_err(|_| PeerHandleError::ChannelClosed)?;

        if config.shutdown_grace.is_zero() {
            join.await.map_err(PeerHandleError::Join)?;
            return Ok(());
        }

        match time::timeout(config.shutdown_grace, join).await {
            Ok(result) => result.map_err(PeerHandleError::Join),
            Err(_) => Err(PeerHandleError::ShutdownTimeout),
        }
    }
}

/// Errors returned by [`PeerHandle`].
#[derive(Debug)]
pub enum PeerHandleError {
    /// The runtime task has already exited and the command channel is closed.
    ChannelClosed,
    /// The runtime command queue is full.
    CommandQueueFull,
    /// The peer actor stopped before responding to a request.
    ActorStopped,
    /// Joining the underlying task failed.
    Join(tokio::task::JoinError),
    /// The actor did not stop within the configured grace window.
    ShutdownTimeout,
}

impl std::fmt::Display for PeerHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelClosed => f.write_str("peer runtime channel closed"),
            Self::CommandQueueFull => f.write_str("peer runtime command channel is full"),
            Self::ActorStopped => f.write_str("peer runtime stopped unexpectedly"),
            Self::Join(err) => write!(f, "peer runtime join error: {err}"),
            Self::ShutdownTimeout => f.write_str("peer runtime shutdown timed out"),
        }
    }
}

impl std::error::Error for PeerHandleError {}

enum PeerCommand<T>
where
    T: crate::api::Transport<Event = TransportEvent>,
{
    Send(SendMeta, Bytes),
    Ack(AckSet),
    Snapshot(oneshot::Sender<TransportResult<PeerSnapshot<T::Snapshot>, T::Error>>),
    DebugSnapshot(oneshot::Sender<TransportResult<DebugSnapshot<T::Snapshot>, T::Error>>),
    Shutdown,
}

/// Spawns a Tokio task that continuously drives the provided `peer`.
///
/// The returned [`PeerHandle`] can be used to queue outbound payloads, acknowledge received data,
/// and capture diagnostic snapshots. Transport events are forwarded over the returned
/// [`tokio::sync::mpsc::Receiver`].
pub fn spawn_peer<T>(
    peer: Peer<T>,
    tick: Duration,
) -> (PeerHandle<T>, Receiver<RuntimeEvent<T::Error>>)
where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    let config = RuntimeConfig::new(tick);
    spawn_peer_with_config(peer, config)
}

/// Spawns a Tokio task using an explicit [`RuntimeConfig`].
pub fn spawn_peer_with_config<T>(
    peer: Peer<T>,
    mut config: RuntimeConfig,
) -> (PeerHandle<T>, Receiver<RuntimeEvent<T::Error>>)
where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    config.normalize();
    let command_capacity = config.command_buffer;
    let event_capacity = config.event_buffer;
    let config = Arc::new(config);
    let (command_tx, command_rx) = mpsc::channel(command_capacity);
    let (event_tx, event_rx) = mpsc::channel(event_capacity);
    let id = peer.id();

    let join = tokio::spawn(run_peer(peer, Arc::clone(&config), command_rx, event_tx));
    let handle = PeerHandle {
        id,
        commands: command_tx,
        join,
        config,
        _marker: PhantomData,
    };
    (handle, event_rx)
}

async fn run_peer<T>(
    mut peer: Peer<T>,
    config: Arc<RuntimeConfig>,
    mut commands: Receiver<PeerCommand<T>>,
    events: Sender<RuntimeEvent<T::Error>>,
) where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    let mut ticker = time::interval(config.tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut consecutive_errors = 0usize;
    let mut last_idle_emit: Option<Instant> = None;
    let mut exit_reason: Option<PeerStopReason> = None;

    loop {
        let control = tokio::select! {
            biased;
            maybe_cmd = commands.recv() => {
                match maybe_cmd {
                    Some(cmd) => handle_command(&mut peer, cmd, &events).await,
                    None => LoopControl::Break(PeerStopReason::CommandChannelClosed),
                }
            }
            _ = ticker.tick() => {
                match peer.drive() {
                    Ok(Some(event)) => {
                        consecutive_errors = 0;
                        match push_event(&events, RuntimeEvent::Transport(event)).await {
                            Ok(_) => LoopControl::Continue,
                            Err(reason) => LoopControl::Break(reason),
                        }
                    }
                    Ok(None) => {
                        consecutive_errors = 0;
                        LoopControl::Continue
                    }
                    Err(err) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        match push_event(&events, RuntimeEvent::TransportError(err)).await {
                            Ok(_) => {
                                if config.max_error_burst > 0 && consecutive_errors >= config.max_error_burst {
                                    let peer_id = peer.id();
                                    warn!(
                                        peer = ?peer_id,
                                        consecutive_errors,
                                        "peer runtime stopping after consecutive transport errors",
                                    );
                                    match push_event(
                                        &events,
                                        RuntimeEvent::Fatal { consecutive_errors },
                                    )
                                    .await
                                    {
                                        Ok(_) => LoopControl::Break(PeerStopReason::Fatal),
                                        Err(reason) => LoopControl::Break(reason),
                                    }
                                } else {
                                    LoopControl::Continue
                                }
                            }
                            Err(reason) => LoopControl::Break(reason),
                        }
                    }
                }
            }
        };

        match control {
            LoopControl::Continue => {
                if config.idle_after != Duration::ZERO {
                    if let Some(idle_for) = peer.idle_for() {
                        if idle_for >= config.idle_after {
                            let should_emit = match last_idle_emit {
                                Some(last) => last.elapsed() >= config.idle_interval,
                                None => true,
                            };
                            if should_emit {
                                match push_event(&events, RuntimeEvent::Idle(idle_for)).await {
                                    Ok(_) => {
                                        last_idle_emit = Some(Instant::now());
                                    }
                                    Err(reason) => {
                                        exit_reason = Some(reason);
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        last_idle_emit = None;
                    }
                }
            }
            LoopControl::Break(reason) => {
                exit_reason = Some(reason);
                break;
            }
        }
    }

    let final_reason = exit_reason.unwrap_or(PeerStopReason::EventChannelClosed);
    if let Err(reason) = push_event(&events, RuntimeEvent::Stopped(final_reason)).await {
        debug!(
            peer = ?peer.id(),
            ?final_reason,
            suppressed = ?reason,
            "failed to deliver final stop event for peer runtime"
        );
    }
}

enum LoopControl {
    Continue,
    Break(PeerStopReason),
}

async fn push_event<E>(
    events: &Sender<RuntimeEvent<E>>,
    event: RuntimeEvent<E>,
) -> Result<(), PeerStopReason>
where
    E: Send + 'static,
{
    match events.try_send(event) {
        Ok(_) => Ok(()),
        Err(TrySendError::Full(event)) => {
            warn!("runtime event channel full; applying backpressure");
            events
                .send(event)
                .await
                .map_err(|_| PeerStopReason::EventChannelClosed)
        }
        Err(TrySendError::Closed(_)) => Err(PeerStopReason::EventChannelClosed),
    }
}

async fn handle_command<T>(
    peer: &mut Peer<T>,
    command: PeerCommand<T>,
    events: &Sender<RuntimeEvent<T::Error>>,
) -> LoopControl
where
    T: crate::api::Transport<Event = TransportEvent> + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Snapshot: Send + 'static,
{
    match command {
        PeerCommand::Send(meta, payload) => {
            peer.enqueue_send(meta, payload);
            LoopControl::Continue
        }
        PeerCommand::Ack(ack) => match peer.handle_ack(ack) {
            Ok(_) => LoopControl::Continue,
            Err(err) => match push_event(events, RuntimeEvent::TransportError(err)).await {
                Ok(_) => LoopControl::Continue,
                Err(reason) => LoopControl::Break(reason),
            },
        },
        PeerCommand::Snapshot(resp) => {
            let _ = resp.send(peer.snapshot());
            LoopControl::Continue
        }
        PeerCommand::DebugSnapshot(resp) => {
            let _ = resp.send(peer.debug_snapshot());
            LoopControl::Continue
        }
        PeerCommand::Shutdown => LoopControl::Break(PeerStopReason::Shutdown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{Caps, Class, ReceivedFrame, RecvMeta, Transport, TransportEvent, TransportResult},
        config::Profile,
        crypto::{nonce::SessionId, session::SessionManager},
        metrics::Metrics,
        peer::CryptoBootstrap,
    };
    use bytes::Bytes;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    struct TestTransport {
        shared: Arc<Mutex<Shared>>,
    }

    #[derive(Default)]
    struct Shared {
        caps: Caps,
        sent: Vec<(SendMeta, Bytes)>,
        inbound: VecDeque<ReceivedFrame>,
    }

    impl TestTransport {
        fn new() -> Self {
            let shared = Shared {
                caps: Caps {
                    etf: false,
                    gso: false,
                    af_xdp: false,
                    io_uring: false,
                    pmtu: 1200,
                    ecn: true,
                },
                ..Shared::default()
            };
            Self {
                shared: Arc::new(Mutex::new(shared)),
            }
        }

        fn push_inbound(&self, frame: ReceivedFrame) {
            let mut guard = self.shared.lock().unwrap();
            guard.inbound.push_back(frame);
        }

        fn take_sent(&self) -> Vec<(SendMeta, Bytes)> {
            let mut guard = self.shared.lock().unwrap();
            std::mem::take(&mut guard.sent)
        }
    }

    impl Transport for TestTransport {
        type Error = std::convert::Infallible;
        type Event = TransportEvent;
        type Snapshot = Caps;

        fn caps(&self) -> Caps {
            self.shared.lock().unwrap().caps
        }

        fn send(&mut self, meta: SendMeta, payload: Bytes) -> TransportResult<(), Self::Error> {
            self.shared.lock().unwrap().sent.push((meta, payload));
            Ok(())
        }

        fn poll(&mut self) -> TransportResult<Option<Self::Event>, Self::Error> {
            let maybe_frame = self.shared.lock().unwrap().inbound.pop_front();
            Ok(maybe_frame.map(TransportEvent::Received))
        }

        fn ack(&mut self, _ack: AckSet) -> TransportResult<(), Self::Error> {
            Ok(())
        }

        fn snapshot(&self) -> TransportResult<Self::Snapshot, Self::Error> {
            Ok(self.caps())
        }
    }

    #[derive(Debug, Clone)]
    struct FatalError;

    impl std::fmt::Display for FatalError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fatal transport error")
        }
    }

    impl std::error::Error for FatalError {}

    #[derive(Clone, Default)]
    struct FailingTransport;

    impl FailingTransport {
        fn new() -> Self {
            Self::default()
        }
    }

    impl Transport for FailingTransport {
        type Error = FatalError;
        type Event = TransportEvent;
        type Snapshot = Caps;

        fn caps(&self) -> Caps {
            Caps::default()
        }

        fn send(&mut self, _meta: SendMeta, _payload: Bytes) -> TransportResult<(), Self::Error> {
            Ok(())
        }

        fn poll(&mut self) -> TransportResult<Option<Self::Event>, Self::Error> {
            Err(FatalError)
        }

        fn ack(&mut self, _ack: AckSet) -> TransportResult<(), Self::Error> {
            Ok(())
        }

        fn snapshot(&self) -> TransportResult<Self::Snapshot, Self::Error> {
            Ok(self.caps())
        }
    }

    #[tokio::test]
    async fn runtime_drives_peer_and_surfaces_events() {
        let transport = TestTransport::new();
        let control = transport.clone();
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());
        let session_id = SessionId::random();
        let master = [0u8; 32];
        let session =
            SessionManager::new(session_id, b"local", b"remote", 0, &master).expect("session");
        let peer = Peer::new(
            crate::peer::PeerId(7),
            crate::config::ProfileName::IntraDc,
            profile,
            transport,
            metrics,
            CryptoBootstrap::Session(session),
        );

        let (handle, mut events) = spawn_peer(peer, Duration::from_millis(5));

        // Queue an outbound payload.
        handle
            .send(
                SendMeta::new(Class::P1, 0, 0, 0),
                Bytes::from_static(b"hello"),
            )
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let sent = control.take_sent();
        assert_eq!(sent.len(), 1);

        // Feed a received frame and ensure it bubbles through the event channel.
        control.push_inbound(ReceivedFrame {
            meta: RecvMeta {
                class: Class::P1,
                stream: 0,
                slot: 0,
                seq: 1,
                len: 5,
                ecn_ce: false,
                received_at: Instant::now(),
            },
            payload: Bytes::from_static(b"world"),
        });

        let mut received_event = None;
        for _ in 0..10 {
            if let Some(event) = tokio::time::timeout(Duration::from_millis(20), events.recv())
                .await
                .ok()
                .flatten()
            {
                if let RuntimeEvent::Transport(TransportEvent::Received(frame)) = event {
                    received_event = Some(frame);
                    break;
                }
            }
        }

        assert!(received_event.is_some());

        // Request snapshot via handle.
        let snapshot = handle.snapshot().await.expect("snapshot").expect("caps");
        assert_eq!(snapshot.id, crate::peer::PeerId(7));

        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn command_channel_backpressure_returns_error() {
        let transport = TestTransport::new();
        let control = transport.clone();
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());
        let session_id = SessionId::random();
        let master = [0u8; 32];
        let session =
            SessionManager::new(session_id, b"local", b"remote", 0, &master).expect("session");
        let peer = Peer::new(
            crate::peer::PeerId(8),
            crate::config::ProfileName::IntraDc,
            profile,
            transport,
            metrics,
            CryptoBootstrap::Session(session),
        );

        let config = RuntimeConfig::new(Duration::from_millis(5)).with_command_buffer(1);
        let (handle, _events) = spawn_peer_with_config(peer, config);

        handle
            .send(SendMeta::new(Class::P1, 0, 0, 0), Bytes::from_static(b"a"))
            .expect("first send succeeds");

        let err = handle
            .send(SendMeta::new(Class::P1, 0, 0, 1), Bytes::from_static(b"b"))
            .expect_err("second send should backpressure");
        assert!(matches!(err, PeerHandleError::CommandQueueFull));

        tokio::time::sleep(Duration::from_millis(20)).await;
        let sent = control.take_sent();
        assert_eq!(sent.len(), 1);

        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn emits_idle_and_stopped_events() {
        let transport = TestTransport::new();
        let control = transport.clone();
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());
        let session_id = SessionId::random();
        let master = [0u8; 32];
        let session =
            SessionManager::new(session_id, b"local", b"remote", 0, &master).expect("session");
        let peer = Peer::new(
            crate::peer::PeerId(9),
            crate::config::ProfileName::IntraDc,
            profile,
            transport,
            metrics,
            CryptoBootstrap::Session(session),
        );

        let config = RuntimeConfig::new(Duration::from_millis(5))
            .with_event_buffer(16)
            .with_idle_threshold(Duration::from_millis(10), Duration::from_millis(10));
        let (handle, mut events) = spawn_peer_with_config(peer, config);

        // Generate an inbound frame to mark activity.
        control.push_inbound(ReceivedFrame {
            meta: RecvMeta {
                class: Class::P1,
                stream: 0,
                slot: 0,
                seq: 1,
                len: 5,
                ecn_ce: false,
                received_at: Instant::now(),
            },
            payload: Bytes::from_static(b"idle"),
        });

        // Drain events until we see the received frame.
        let mut saw_received = false;
        for _ in 0..10 {
            if let Some(event) = tokio::time::timeout(Duration::from_millis(20), events.recv())
                .await
                .ok()
                .flatten()
            {
                match event {
                    RuntimeEvent::Transport(TransportEvent::Received(_)) => {
                        saw_received = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
        assert!(saw_received, "expected to observe received event");

        // Await an idle notification.
        let idle_event = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                match events.recv().await {
                    Some(RuntimeEvent::Idle(duration)) => break Some(duration),
                    Some(_) => continue,
                    None => break None,
                }
            }
        })
        .await
        .ok()
        .flatten();

        let idle_duration = idle_event.expect("idle event not emitted");
        assert!(
            idle_duration >= Duration::from_millis(10),
            "idle duration shorter than threshold"
        );

        handle.shutdown().await.expect("shutdown");

        // Expect the runtime to surface a stopped event with shutdown reason.
        let stopped = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                match events.recv().await {
                    Some(RuntimeEvent::Stopped(reason)) => break Some(reason),
                    Some(_) => continue,
                    None => break None,
                }
            }
        })
        .await
        .ok()
        .flatten();

        assert_eq!(
            stopped,
            Some(PeerStopReason::Shutdown),
            "expected shutdown stop reason"
        );
    }

    #[tokio::test]
    async fn emits_fatal_event_after_consecutive_errors() {
        let transport = FailingTransport::new();
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let profile = Arc::new(Profile::intra_dc_defaults());
        let session_id = SessionId::random();
        let master = [0u8; 32];
        let session =
            SessionManager::new(session_id, b"local", b"remote", 0, &master).expect("session");
        let peer = Peer::new(
            crate::peer::PeerId(10),
            crate::config::ProfileName::IntraDc,
            profile,
            transport,
            metrics,
            CryptoBootstrap::Session(session),
        );

        let config = RuntimeConfig::new(Duration::from_millis(5))
            .with_event_buffer(16)
            .with_max_error_burst(2);
        let (handle, mut events) = spawn_peer_with_config(peer, config);

        let mut fatal_seen = false;
        let mut stop_reason = None;

        for _ in 0..8 {
            if let Some(event) = tokio::time::timeout(Duration::from_millis(50), events.recv())
                .await
                .ok()
                .flatten()
            {
                match event {
                    RuntimeEvent::TransportError(_) => {}
                    RuntimeEvent::Fatal { consecutive_errors } => {
                        fatal_seen = true;
                        assert!(
                            consecutive_errors >= 2,
                            "expected at least two consecutive errors"
                        );
                    }
                    RuntimeEvent::Stopped(reason) => {
                        stop_reason = Some(reason);
                        break;
                    }
                    other => panic!("unexpected runtime event: {other:?}"),
                }
            }
        }

        assert!(fatal_seen, "expected fatal event after consecutive errors");
        assert_eq!(
            stop_reason,
            Some(PeerStopReason::Fatal),
            "expected fatal stop reason"
        );

        if let Err(err) = handle.shutdown().await {
            assert!(
                matches!(
                    err,
                    PeerHandleError::ChannelClosed | PeerHandleError::ShutdownTimeout
                ),
                "unexpected shutdown error: {err}"
            );
        }
    }
}
