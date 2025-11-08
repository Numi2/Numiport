#![cfg(feature = "transport-api")]

// Public transport API exposed to integrators.
// Numan Thabit 2025 November weekend fun
use std::{fmt, time::Instant};

use bytes::Bytes;

/// Service class used in scheduling and budgeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Critical control plane traffic.
    P0,
    /// High priority data plane traffic.
    P1,
    /// Medium priority data plane traffic.
    P2,
    /// Best-effort traffic.
    P3,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Class::P0 => "p0",
            Class::P1 => "p1",
            Class::P2 => "p2",
            Class::P3 => "p3",
        };
        f.write_str(label)
    }
}

impl Class {
    /// Returns the numeric index associated with the class.
    pub const fn as_index(self) -> usize {
        match self {
            Class::P0 => 0,
            Class::P1 => 1,
            Class::P2 => 2,
            Class::P3 => 3,
        }
    }

    /// Returns an array of all classes in priority order.
    pub const fn all() -> [Class; 4] {
        [Class::P0, Class::P1, Class::P2, Class::P3]
    }
}

/// Metadata describing an outbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMeta {
    /// Service class the payload should be scheduled under.
    pub class: Class,
    /// Stream identifier scoped to the peer.
    pub stream: u32,
    /// Slot number associated with the payload.
    pub slot: u64,
    /// Sequence number within the slot/stream namespace.
    pub seq: u32,
    /// Whether the packet should be marked ECN-capable.
    pub ecn_capable: bool,
}

impl SendMeta {
    /// Convenience constructor.
    pub fn new(class: Class, stream: u32, slot: u64, seq: u32) -> Self {
        Self {
            class,
            stream,
            slot,
            seq,
            ecn_capable: true,
        }
    }
}

/// Capability flags advertised by a transport implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps {
    /// Supports ETF queueing via SO_TXTIME.
    pub etf: bool,
    /// Supports UDP Generic Segmentation Offload.
    pub gso: bool,
    /// Supports AF_XDP zero-copy sockets.
    pub af_xdp: bool,
    /// Supports io_uring backend.
    pub io_uring: bool,
    /// Path MTU currently negotiated.
    pub pmtu: u16,
    /// Supports Explicit Congestion Notification.
    pub ecn: bool,
}

impl Caps {
    /// Returns `true` if ETF pacing is available.
    pub fn has_etf(&self) -> bool {
        self.etf
    }

    /// Returns `true` if batching via GSO is available.
    pub fn has_gso(&self) -> bool {
        self.gso
    }
}

/// Compact acknowledgement set encoded as inclusive ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckSet {
    /// Stream identifier.
    pub stream: u32,
    /// Slot identifier.
    pub slot: u64,
    /// Ranges acknowledged for the slot.
    pub ranges: Vec<AckRange>,
}

impl AckSet {
    /// Creates a new acknowledgement set.
    pub fn new(stream: u32, slot: u64, ranges: Vec<AckRange>) -> Self {
        Self {
            stream,
            slot,
            ranges,
        }
    }

    /// Returns true when no ranges are present.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Inclusive acknowledgement range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// First sequence number acknowledged (inclusive).
    pub start: u32,
    /// Last sequence number acknowledged (inclusive).
    pub end: u32,
}

impl AckRange {
    /// Creates a new acknowledgement range.
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Number of acknowledged sequence numbers within the range.
    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

/// Metadata describing an inbound payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    /// Service class assigned during scheduling.
    pub class: Class,
    /// Stream identifier.
    pub stream: u32,
    /// Slot identifier.
    pub slot: u64,
    /// Sequence identifier.
    pub seq: u32,
    /// Payload length in bytes.
    pub len: usize,
    /// Whether ECN CE was observed on receipt.
    pub ecn_ce: bool,
    /// Timestamp when the packet was dequeued by the transport.
    pub received_at: Instant,
}

/// Events yielded by [`Transport::poll`].
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A payload has been received.
    Received(ReceivedFrame),
    /// Transport completed an internal maintenance action.
    Maintenance,
    /// Transport is currently idle.
    Idle,
}

/// A received frame with its metadata.
#[derive(Debug, Clone)]
pub struct ReceivedFrame {
    /// Metadata describing the received payload.
    pub meta: RecvMeta,
    /// Payload bytes.
    pub payload: Bytes,
}

/// Result alias used within transport operations.
pub type TransportResult<T, E> = Result<T, E>;

/// Public transport trait to be implemented by backend providers.
pub trait Transport {
    /// Error type returned by the transport.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Event type returned from [`Transport::poll`].
    type Event;
    /// Snapshot type surfaced through [`Transport::snapshot`].
    type Snapshot;

    /// Returns the static capability set for this transport instance.
    fn caps(&self) -> Caps;

    /// Queues an outbound payload for transmission.
    fn send(&mut self, meta: SendMeta, payload: Bytes) -> TransportResult<(), Self::Error>;

    /// Polls for transport events.
    fn poll(&mut self) -> TransportResult<Option<Self::Event>, Self::Error>;

    /// Submits acknowledgement information to the transport.
    fn ack(&mut self, ack: AckSet) -> TransportResult<(), Self::Error>;

    /// Captures a diagnostic snapshot of the transport state.
    fn snapshot(&self) -> TransportResult<Self::Snapshot, Self::Error>;
}
