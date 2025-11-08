// Numiport transport public library surface.
// Numan Thabit 2025 November weekend fun

pub mod config;

pub mod clock;

pub mod ack;

pub mod crypto;

pub mod wire;

#[cfg(feature = "transport-api")]
pub mod sched;

pub mod metrics;

pub mod repair;

pub mod topo;

#[cfg(feature = "transport-api")]
pub mod api;

#[cfg(feature = "transport-api")]
pub mod peer;

#[cfg(feature = "transport-api")]
pub mod runtime;

pub use config::{Config, ConfigError, Profile, ProfileName, Profiles};

pub use ack::{
    AckDecoder, AckEncoder, AckError, AckRange as AckRleRange, ReplayOccupancy, ReplayWindow,
};

pub use crypto::{
    aead::{
        self, AeadError, AeadKey, Algorithm, Nonce, TAG_LEN as AEAD_TAG_LEN, XCHACHA20_NONCE_LEN,
    },
    hkdf::{derive as hkdf_derive, derive_aead_key, derive_header_mac_key, HkdfError},
    hmac::{
        compute as compute_header_mac, verify as verify_header_mac, HeaderMacError, HeaderMacKey,
        HEADER_MAC_LEN,
    },
    nonce::{
        derive_nonce, derive_nonce_salt, Direction, SessionId, SessionStore, SessionStoreError,
        NONCE_LEN, NONCE_SALT_LEN,
    },
    session::{SessionError, SessionManager, SessionSecrets},
};

pub use wire::{
    build_aad, ecn_from_tclass, ecn_from_tos, parse_packet, with_ecn, EcnCodepoint, NumiHdr,
    PacketParts, ServiceClass, Tlv, TlvBuilder, TlvCursor, TlvType, NUMI_HDR_LEN, TLV_ALIGN,
};

#[cfg(feature = "transport-api")]
pub use api::{
    AckRange, AckSet, Caps, Class, ReceivedFrame, RecvMeta, SendMeta, Transport, TransportEvent,
    TransportResult,
};

#[cfg(feature = "transport-api")]
pub use peer::{
    CryptoBootstrap, DebugSnapshot, EcnAggregate, Peer, PeerId, PeerSnapshot, PeerStatistics,
    SlotMetrics,
};

#[cfg(feature = "transport-api")]
pub use runtime::{
    spawn_peer, spawn_peer_with_config, PeerHandle, PeerHandleError, PeerStopReason, RuntimeConfig,
    RuntimeEvent,
};

pub use repair::{RepairInventory, RepairKey, RepairService, RepairTracker};

pub use metrics::{Metrics, MetricsError};
