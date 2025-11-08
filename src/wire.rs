// Wire format primitives: fixed header, TLV encoding, and helpers.
// Numan Thabit 2025

use std::convert::TryFrom;

use crate::crypto::{
    aead::{self, AeadKey, Nonce},
    hmac::{self, HeaderMacError, HeaderMacKey, HEADER_MAC_LEN},
};

use thiserror::Error;

/// Length of the fixed header in bytes (cache-aligned).
pub const NUMI_HDR_LEN: usize = 32;

/// Alignment for TLV records (bytes).
pub const TLV_ALIGN: usize = 4;

const TLV_HEADER_LEN: usize = 3; // type (u8) + length (u16)
const MAX_FLAGS: u8 = 0b11_1111; // 6 bits

/// Service class carried on the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceClass {
    /// Critical control plane traffic.
    P0 = 0,
    /// High priority data plane shreds.
    P1 = 1,
    /// Repair plane traffic.
    P2 = 2,
    /// Background / best-effort.
    P3 = 3,
}

impl ServiceClass {
    /// Returns all classes in priority order.
    pub const fn all() -> [ServiceClass; 4] {
        [
            ServiceClass::P0,
            ServiceClass::P1,
            ServiceClass::P2,
            ServiceClass::P3,
        ]
    }
}

impl TryFrom<u8> for ServiceClass {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ServiceClass::P0),
            1 => Ok(ServiceClass::P1),
            2 => Ok(ServiceClass::P2),
            3 => Ok(ServiceClass::P3),
            other => Err(WireError::InvalidClass(other)),
        }
    }
}

impl From<ServiceClass> for u8 {
    fn from(class: ServiceClass) -> Self {
        class as u8
    }
}

#[cfg(feature = "transport-api")]
impl From<ServiceClass> for crate::api::Class {
    fn from(value: ServiceClass) -> Self {
        match value {
            ServiceClass::P0 => crate::api::Class::P0,
            ServiceClass::P1 => crate::api::Class::P1,
            ServiceClass::P2 => crate::api::Class::P2,
            ServiceClass::P3 => crate::api::Class::P3,
        }
    }
}

#[cfg(feature = "transport-api")]
impl From<crate::api::Class> for ServiceClass {
    fn from(value: crate::api::Class) -> Self {
        match value {
            crate::api::Class::P0 => ServiceClass::P0,
            crate::api::Class::P1 => ServiceClass::P1,
            crate::api::Class::P2 => ServiceClass::P2,
            crate::api::Class::P3 => ServiceClass::P3,
        }
    }
}

/// Bit-flags carried in the header.
pub mod flags {
    /// ACK-only frame; no payload.
    pub const ACK_ONLY: u8 = 0b000001;
    /// Contains negative acknowledgements.
    pub const NACK: u8 = 0b000010;
    /// FEC metadata present in TLVs.
    pub const FEC: u8 = 0b000100;
    /// PSK identifier present.
    pub const PSK_ID: u8 = 0b001000;
    /// Control-plane message.
    pub const CTRL: u8 = 0b010000;
    /// ECN summary TLV included.
    pub const ECN_SUMMARY: u8 = 0b100000;
}

/// Wire-level error.
#[derive(Debug, Error)]
pub enum WireError {
    /// Buffer shorter than required.
    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    /// Unsupported protocol version.
    #[error("unsupported header version {0}")]
    UnsupportedVersion(u8),

    /// Invalid service class value.
    #[error("invalid service class {0}")]
    InvalidClass(u8),

    /// Flag value overflowed 6-bit allocation.
    #[error("flag value {0:#08b} exceeds 6-bit range")]
    FlagsOverflow(u8),

    /// Reserved header field was non-zero.
    #[error("reserved header field must be zero (found {0:#06x})")]
    ReservedNotZero(u16),

    /// TLV length exceeds encoding range.
    #[error("tlv value length {len} exceeds u16 range for type {type_id}")]
    InvalidTlvLength { type_id: u8, len: usize },

    /// TLV padding would overflow or extend past buffer.
    #[error("tlv for type {type_id} exceeds buffer")]
    TlvOutOfBounds { type_id: u8 },

    /// Duplicate TLV encountered when a unique one was expected.
    #[error("duplicate tlv type {type_id}")]
    DuplicateTlv { type_id: u8 },

    /// Encountered malformed TLV (e.g., non-zero length for END).
    #[error("malformed tlv type {type_id}: {reason}")]
    MalformedTlv { type_id: u8, reason: &'static str },

    /// Missing required END TLV terminator.
    #[error("missing END tlv terminator")]
    MissingEndTlv,

    /// Missing HDR_MAC TLV when verification was requested.
    #[error("missing HDR_MAC tlv")]
    MissingHdrMac,

    /// HDR_MAC TLV had an unexpected length.
    #[error("invalid HDR_MAC length {0}")]
    InvalidHdrMacLength(u16),

    /// Header MAC verification failed.
    #[error("header mac error: {0}")]
    HeaderMac(#[from] HeaderMacError),

    /// Declared payload length exceeds remaining bytes.
    #[error("payload length {declared} exceeds remaining bytes {available}")]
    PayloadUnderrun { declared: usize, available: usize },

    /// AEAD tag length mismatch.
    #[error("invalid tag length: expected {expected}, got {actual}")]
    InvalidTagLength { expected: usize, actual: usize },

    /// AEAD failure during decrypt.
    #[error("aead error: {0}")]
    Aead(#[from] aead::AeadError),
}

/// Fixed header as carried on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumiHdr {
    /// Protocol version.
    pub version: u8,
    /// Service class.
    pub class: ServiceClass,
    /// 6-bit flag field.
    pub flags: u8,
    /// Absolute slot number.
    pub slot: u64,
    /// Stream identifier.
    pub stream: u32,
    /// Sequence number within the (peer, slot, stream) namespace.
    pub seq: u32,
    /// Total shards (data + coding) in FEC group; zero if unused.
    pub fec_total: u16,
    /// Shred index within FEC group; zero if unused.
    pub shred_idx: u16,
    /// Payload length in bytes (excluding AEAD tag).
    pub payload_len: u16,
}

impl NumiHdr {
    /// Encodes the header into a byte array.
    pub fn encode(&self) -> Result<[u8; NUMI_HDR_LEN], WireError> {
        if self.flags > MAX_FLAGS {
            return Err(WireError::FlagsOverflow(self.flags));
        }

        let mut buf = [0u8; NUMI_HDR_LEN];
        buf[0] = self.version;
        buf[1] = (self.flags << 2) | (u8::from(self.class) & 0b11);
        buf[2..10].copy_from_slice(&self.slot.to_be_bytes());
        buf[10..14].copy_from_slice(&self.stream.to_be_bytes());
        buf[14..18].copy_from_slice(&self.seq.to_be_bytes());
        buf[18..20].copy_from_slice(&self.fec_total.to_be_bytes());
        buf[20..22].copy_from_slice(&self.shred_idx.to_be_bytes());
        buf[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        // bytes 24..32 reserved (zero-filled by default)
        Ok(buf)
    }

    /// Serialises the header into the supplied buffer.
    pub fn write_into(&self, out: &mut [u8]) -> Result<(), WireError> {
        if out.len() < NUMI_HDR_LEN {
            return Err(WireError::BufferTooShort {
                expected: NUMI_HDR_LEN,
                actual: out.len(),
            });
        }
        let encoded = self.encode()?;
        out[..NUMI_HDR_LEN].copy_from_slice(&encoded);
        Ok(())
    }

    /// Parses a header from the provided buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < NUMI_HDR_LEN {
            return Err(WireError::BufferTooShort {
                expected: NUMI_HDR_LEN,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        let combined = bytes[1];
        let class_bits = combined & 0b11;
        let flags = combined >> 2;

        let slot = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let stream = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
        let seq = u32::from_be_bytes(bytes[14..18].try_into().unwrap());
        let fec_total = u16::from_be_bytes(bytes[18..20].try_into().unwrap());
        let shred_idx = u16::from_be_bytes(bytes[20..22].try_into().unwrap());
        let payload_len = u16::from_be_bytes(bytes[22..24].try_into().unwrap());
        let reserved = u16::from_be_bytes(bytes[24..26].try_into().unwrap());

        if reserved != 0 {
            return Err(WireError::ReservedNotZero(reserved));
        }

        let class = ServiceClass::try_from(class_bits)?;

        Ok(Self {
            version,
            class,
            flags,
            slot,
            stream,
            seq,
            fec_total,
            shred_idx,
            payload_len,
        })
    }
}

/// Parsed packet components.
#[derive(Debug, Clone)]
pub struct PacketParts<'a> {
    /// Parsed header.
    pub header: NumiHdr,
    /// Slice covering the TLV section (including END and padding).
    pub tlv_bytes: &'a [u8],
    /// Payload slice (len = header.payload_len).
    pub payload: &'a [u8],
    /// Trailing bytes (e.g. AEAD tag).
    pub remainder: &'a [u8],
}

impl<'a> PacketParts<'a> {
    /// Returns the TLV with the provided type when present, ensuring uniqueness.
    pub fn tlv(&self, kind: TlvType) -> Result<Option<Tlv<'a>>, WireError> {
        find_unique_tlv(self.tlv_bytes, kind)
    }

    /// Verifies the header MAC using the supplied key.
    pub fn verify_header_mac(&self, key: &HeaderMacKey) -> Result<(), WireError> {
        let tag_tlv = self.tlv(TlvType::HdrMac)?.ok_or(WireError::MissingHdrMac)?;
        if tag_tlv.length != HEADER_MAC_LEN as u16 {
            return Err(WireError::InvalidHdrMacLength(tag_tlv.length));
        }
        let aad = build_aad(&self.header, self.tlv_bytes)?;
        hmac::verify(key, &aad, tag_tlv.value)?;
        Ok(())
    }

    /// Decrypts the payload using the provided AEAD context.
    pub fn decrypt_payload(&self, key: &AeadKey, nonce: &Nonce) -> Result<Vec<u8>, WireError> {
        let aad = build_aad(&self.header, self.tlv_bytes)?;
        let tag_len = key.tag_len();
        if self.remainder.len() != tag_len {
            return Err(WireError::InvalidTagLength {
                expected: tag_len,
                actual: self.remainder.len(),
            });
        }

        let mut ciphertext = Vec::with_capacity(self.payload.len() + tag_len);
        ciphertext.extend_from_slice(self.payload);
        ciphertext.extend_from_slice(self.remainder);
        Ok(aead::open(key, nonce, &aad, &ciphertext)?)
    }
}

/// Parses a full packet into header, TLVs, payload, and remainder.
pub fn parse_packet(bytes: &[u8]) -> Result<PacketParts<'_>, WireError> {
    if bytes.len() < NUMI_HDR_LEN {
        return Err(WireError::BufferTooShort {
            expected: NUMI_HDR_LEN,
            actual: bytes.len(),
        });
    }

    let header = NumiHdr::parse(&bytes[..NUMI_HDR_LEN])?;
    let mut cursor = TlvCursor::new(&bytes[NUMI_HDR_LEN..]);

    let mut tlv_len: Option<usize> = None;
    for item in cursor.by_ref() {
        let tlv = item?;
        if tlv.type_id == TlvType::End as u8 {
            tlv_len = Some(cursor.consumed_len());
            break;
        }
    }

    let tlv_len = tlv_len.ok_or(WireError::MissingEndTlv)?;
    let tlv_start = NUMI_HDR_LEN;
    let tlv_end = tlv_start + tlv_len;
    if bytes.len() < tlv_end {
        return Err(WireError::BufferTooShort {
            expected: tlv_end,
            actual: bytes.len(),
        });
    }

    let payload_len = header.payload_len as usize;
    let available = bytes.len().saturating_sub(tlv_end);
    if available < payload_len {
        return Err(WireError::PayloadUnderrun {
            declared: payload_len,
            available,
        });
    }

    let payload_end = tlv_end + payload_len;
    let payload = &bytes[tlv_end..payload_end];
    let remainder = &bytes[payload_end..];

    Ok(PacketParts {
        header,
        tlv_bytes: &bytes[tlv_start..tlv_end],
        payload,
        remainder,
    })
}

fn find_unique_tlv<'a>(buf: &'a [u8], kind: TlvType) -> Result<Option<Tlv<'a>>, WireError> {
    let cursor = TlvCursor::new(buf);
    let mut found: Option<Tlv<'a>> = None;
    for item in cursor {
        let tlv = item?;
        if tlv.type_id == kind as u8 {
            if found.is_some() {
                return Err(WireError::DuplicateTlv {
                    type_id: tlv.type_id,
                });
            }
            found = Some(tlv);
        }
    }
    Ok(found)
}

/// TLV type identifiers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvType {
    End = 0,
    Caps = 1,
    PskId = 2,
    AckRle = 3,
    NackList = 4,
    Pmtu = 5,
    EcnSummary = 6,
    RetryCookie = 7,
    HdrMac = 8,
}

impl TlvType {
    fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(TlvType::End),
            1 => Some(TlvType::Caps),
            2 => Some(TlvType::PskId),
            3 => Some(TlvType::AckRle),
            4 => Some(TlvType::NackList),
            5 => Some(TlvType::Pmtu),
            6 => Some(TlvType::EcnSummary),
            7 => Some(TlvType::RetryCookie),
            8 => Some(TlvType::HdrMac),
            _ => None,
        }
    }
}

/// Parsed TLV view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Raw type identifier.
    pub type_id: u8,
    /// Declared value length.
    pub length: u16,
    /// Value bytes (length = `length`).
    pub value: &'a [u8],
    raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Returns the enum variant when known.
    pub fn kind(&self) -> Option<TlvType> {
        TlvType::from_raw(self.type_id)
    }

    /// Returns the full encoded TLV including padding.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

/// Cursor over TLV records.
pub struct TlvCursor<'a> {
    buf: &'a [u8],
    offset: usize,
    finished: bool,
}

impl<'a> TlvCursor<'a> {
    /// Creates a TLV cursor from the provided buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            offset: 0,
            finished: false,
        }
    }

    /// Returns total bytes consumed so far.
    pub fn consumed_len(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for TlvCursor<'a> {
    type Item = Result<Tlv<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        if self.offset >= self.buf.len() {
            // No more TLVs.
            self.finished = true;
            return None;
        }

        if self.buf.len() - self.offset < TLV_HEADER_LEN {
            self.finished = true;
            return Some(Err(WireError::MissingEndTlv));
        }

        let type_id = self.buf[self.offset];
        let len = u16::from_be_bytes(
            self.buf[self.offset + 1..self.offset + 3]
                .try_into()
                .unwrap(),
        ) as usize;

        let header_end = self.offset + TLV_HEADER_LEN;
        let total_len = match align_tlv_len(len) {
            Some(total) => total,
            None => {
                self.finished = true;
                return Some(Err(WireError::InvalidTlvLength { type_id, len }));
            }
        };

        let tlv_end = match self.offset.checked_add(total_len) {
            Some(end) => end,
            None => {
                self.finished = true;
                return Some(Err(WireError::TlvOutOfBounds { type_id }));
            }
        };

        if tlv_end > self.buf.len() {
            self.finished = true;
            return Some(Err(WireError::TlvOutOfBounds { type_id }));
        }

        let value_end = match header_end.checked_add(len) {
            Some(end) => end,
            None => {
                self.finished = true;
                return Some(Err(WireError::TlvOutOfBounds { type_id }));
            }
        };

        if value_end > tlv_end {
            self.finished = true;
            return Some(Err(WireError::TlvOutOfBounds { type_id }));
        }

        if type_id == TlvType::End as u8 && len != 0 {
            self.finished = true;
            return Some(Err(WireError::MalformedTlv {
                type_id,
                reason: "END must have zero length",
            }));
        }

        let value = &self.buf[header_end..value_end];
        let raw = &self.buf[self.offset..tlv_end];
        self.offset = tlv_end;
        if type_id == TlvType::End as u8 {
            self.finished = true;
        }

        Some(Ok(Tlv {
            type_id,
            length: len as u16,
            value,
            raw,
        }))
    }
}

fn align_tlv_len(value_len: usize) -> Option<usize> {
    let base = TLV_HEADER_LEN.checked_add(value_len)?;
    align_up(base, TLV_ALIGN)
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    if align == 0 {
        return Some(value);
    }
    let remainder = value % align;
    if remainder == 0 {
        Some(value)
    } else {
        let padding = align - remainder;
        value.checked_add(padding)
    }
}

/// Builder for TLV-encoded sections.
#[derive(Debug, Default, Clone)]
pub struct TlvBuilder {
    buf: Vec<u8>,
    finished: bool,
}

impl TlvBuilder {
    /// Creates a new TLV builder.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            finished: false,
        }
    }

    /// Creates a builder with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            finished: false,
        }
    }

    /// Adds a TLV with the provided value bytes.
    pub fn push(&mut self, kind: TlvType, value: &[u8]) -> Result<&mut Self, WireError> {
        self.push_raw(kind as u8, value)
    }

    /// Adds a TLV with a raw type identifier.
    pub fn push_raw(&mut self, type_id: u8, value: &[u8]) -> Result<&mut Self, WireError> {
        if self.finished {
            return Err(WireError::MalformedTlv {
                type_id,
                reason: "TLV builder finished",
            });
        }
        if type_id == TlvType::End as u8 {
            if !value.is_empty() {
                return Err(WireError::MalformedTlv {
                    type_id,
                    reason: "END TLV must have empty value",
                });
            }
            self.finished = true;
        }

        if value.len() > u16::MAX as usize {
            return Err(WireError::InvalidTlvLength {
                type_id,
                len: value.len(),
            });
        }

        let pad_total = align_tlv_len(value.len()).ok_or(WireError::InvalidTlvLength {
            type_id,
            len: value.len(),
        })?;
        let pad = pad_total - (TLV_HEADER_LEN + value.len());

        self.buf.push(type_id);
        self.buf
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        self.buf.extend(std::iter::repeat_n(0u8, pad));

        Ok(self)
    }

    /// Ensures an END TLV terminator is present and returns the encoded bytes.
    pub fn finish(mut self) -> Result<Vec<u8>, WireError> {
        if !self.finished {
            self.push(TlvType::End, &[])?;
        }
        Ok(self.buf)
    }
}

/// Builds AAD covering the header and TLVs (excluding HDR_MAC & RETRY_COOKIE).
pub fn build_aad(header: &NumiHdr, tlv_bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut aad = Vec::with_capacity(NUMI_HDR_LEN + tlv_bytes.len());
    aad.extend_from_slice(&header.encode()?);

    let cursor = TlvCursor::new(tlv_bytes);
    for item in cursor {
        let tlv = item?;
        match tlv.kind() {
            Some(TlvType::HdrMac) | Some(TlvType::RetryCookie) => {}
            _ => aad.extend_from_slice(tlv.raw()),
        }
    }

    Ok(aad)
}

/// ECN codepoints extracted from TOS/TCLASS.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    /// Not ECN capable transport.
    NotEct = 0b00,
    /// ECN capable, ECT(1).
    Ect1 = 0b01,
    /// ECN capable, ECT(0).
    Ect0 = 0b10,
    /// Congestion experienced.
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Extracts from the lower two bits.
    pub fn from_tos(tos: u8) -> Self {
        match tos & 0b11 {
            0b01 => EcnCodepoint::Ect1,
            0b10 => EcnCodepoint::Ect0,
            0b11 => EcnCodepoint::Ce,
            _ => EcnCodepoint::NotEct,
        }
    }

    /// Applies the ECN bits to a DS field.
    pub fn apply(self, tos: u8) -> u8 {
        (tos & !0b11) | (self as u8)
    }
}

/// Extracts ECN codepoint from IPv4 TOS value.
pub fn ecn_from_tos(tos: u8) -> EcnCodepoint {
    EcnCodepoint::from_tos(tos)
}

/// Extracts ECN codepoint from IPv6 traffic class value.
pub fn ecn_from_tclass(tclass: u8) -> EcnCodepoint {
    EcnCodepoint::from_tos(tclass)
}

/// Applies ECN bits to a TOS byte.
pub fn with_ecn(tos: u8, ecn: EcnCodepoint) -> u8 {
    ecn.apply(tos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::XCHACHA20_NONCE_LEN;
    use proptest::prelude::*;

    fn arb_value() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..64)
    }

    #[test]
    fn header_round_trip() {
        let hdr = NumiHdr {
            version: 1,
            class: ServiceClass::P2,
            flags: flags::FEC | flags::ECN_SUMMARY,
            slot: 42,
            stream: 3,
            seq: 15,
            fec_total: 32,
            shred_idx: 7,
            payload_len: 1200,
        };

        let bytes = hdr.encode().unwrap();
        let parsed = NumiHdr::parse(&bytes).unwrap();
        assert_eq!(hdr, parsed);
    }

    proptest! {
        #[test]
        fn tlv_round_trip(entries in prop::collection::vec((0u8..=u8::MAX, arb_value()), 0..16)) {
            let mut builder = TlvBuilder::new();
            for (mut ty, val) in entries.clone() {
                if ty == TlvType::End as u8 {
                    ty = ty.wrapping_add(1);
                }
                builder.push_raw(ty, &val).unwrap();
            }
            let encoded = builder.finish().unwrap();

            let mut iter = TlvCursor::new(&encoded);
            let mut decoded = Vec::new();
            for item in iter.by_ref() {
                let tlv = item.unwrap();
                if tlv.type_id == TlvType::End as u8 { break; }
                decoded.push((tlv.type_id, tlv.value.to_vec()));
                assert_eq!(tlv.raw().len() % TLV_ALIGN, 0);
            }

            assert_eq!(entries.len(), decoded.len());
            for (a, b) in entries.into_iter().zip(decoded.into_iter()) {
                let expected_type = if a.0 == TlvType::End as u8 { a.0.wrapping_add(1) } else { a.0 };
                assert_eq!(expected_type, b.0);
                assert_eq!(a.1, b.1);
            }
        }

        #[test]
        fn packet_split_round_trip(payload in arb_value(), tlvs in prop::collection::vec((1u8..=8u8, arb_value()), 0..6)) {
            let mut builder = TlvBuilder::new();
            for (ty, val) in tlvs.iter() {
                builder.push_raw(*ty, val).unwrap();
            }
            let tlv_bytes = builder.finish().unwrap();

            let header = NumiHdr {
                version: 1,
                class: ServiceClass::P1,
                flags: 0,
                slot: 99,
                stream: 7,
                seq: 123,
                fec_total: 0,
                shred_idx: 0,
                payload_len: payload.len() as u16,
            };

            let mut packet = header.encode().unwrap().to_vec();
            packet.extend_from_slice(&tlv_bytes);
            packet.extend_from_slice(&payload);
            packet.extend_from_slice(&[0u8; 16]); // fake tag

            let parts = parse_packet(&packet).unwrap();
            assert_eq!(parts.payload, &payload[..]);
            assert_eq!(parts.remainder.len(), 16);

            let collected: Vec<(u8, Vec<u8>)> = TlvCursor::new(parts.tlv_bytes)
                .filter_map(|res| res.ok())
                .take_while(|tlv| tlv.type_id != TlvType::End as u8)
                .map(|tlv| (tlv.type_id, tlv.value.to_vec()))
                .collect();

            assert_eq!(tlvs, collected);
        }
    }

    #[test]
    fn header_mac_verification_succeeds() {
        let mut builder = TlvBuilder::new();
        builder
            .push(TlvType::HdrMac, &[0u8; HEADER_MAC_LEN])
            .unwrap();
        let mut tlv_bytes = builder.finish().unwrap();

        let header = NumiHdr {
            version: 1,
            class: ServiceClass::P0,
            flags: flags::ACK_ONLY,
            slot: 10,
            stream: 0,
            seq: 1,
            fec_total: 0,
            shred_idx: 0,
            payload_len: 0,
        };

        let aad = build_aad(&header, &tlv_bytes).unwrap();
        let key = HeaderMacKey::new([0xAA; 32]);
        let mac = hmac::compute(&key, &aad);

        let mut cursor = TlvCursor::new(&tlv_bytes);
        while let Some(item) = cursor.next() {
            let tlv = item.unwrap();
            let end = cursor.consumed_len();
            let start = end - tlv.raw().len();
            if tlv.type_id == TlvType::HdrMac as u8 {
                let value_offset = start + TLV_HEADER_LEN;
                tlv_bytes[value_offset..value_offset + HEADER_MAC_LEN].copy_from_slice(&mac);
                break;
            }
        }

        let mut packet = header.encode().unwrap().to_vec();
        packet.extend_from_slice(&tlv_bytes);

        let parts = parse_packet(&packet).unwrap();
        assert!(parts.verify_header_mac(&key).is_ok());
    }

    #[test]
    fn duplicate_hdr_mac_is_rejected() {
        let mut builder = TlvBuilder::new();
        builder
            .push(TlvType::HdrMac, &[0u8; HEADER_MAC_LEN])
            .unwrap();
        builder
            .push(TlvType::HdrMac, &[0u8; HEADER_MAC_LEN])
            .unwrap();
        let tlv_bytes = builder.finish().unwrap();

        let header = NumiHdr {
            version: 1,
            class: ServiceClass::P1,
            flags: 0,
            slot: 5,
            stream: 0,
            seq: 0,
            fec_total: 0,
            shred_idx: 0,
            payload_len: 0,
        };

        let mut packet = header.encode().unwrap().to_vec();
        packet.extend_from_slice(&tlv_bytes);

        let parts = parse_packet(&packet).unwrap();
        let err = parts.tlv(TlvType::HdrMac).unwrap_err();
        assert!(
            matches!(err, WireError::DuplicateTlv { type_id } if type_id == TlvType::HdrMac as u8)
        );
    }

    #[test]
    fn decrypts_payload_after_mac() {
        let plaintext = b"payload bytes".to_vec();
        let header_mac_key = HeaderMacKey::new([0x10; 32]);
        let aead_key = AeadKey::xchacha([0x20; 32]);
        let nonce = Nonce::xchacha([0x30; XCHACHA20_NONCE_LEN]);

        let mut builder = TlvBuilder::new();
        builder
            .push(TlvType::HdrMac, &[0u8; HEADER_MAC_LEN])
            .unwrap();
        let mut tlv_bytes = builder.finish().unwrap();

        let header = NumiHdr {
            version: 1,
            class: ServiceClass::P1,
            flags: 0,
            slot: 77,
            stream: 2,
            seq: 9,
            fec_total: 0,
            shred_idx: 0,
            payload_len: plaintext.len() as u16,
        };

        let aad = build_aad(&header, &tlv_bytes).unwrap();
        let mac = hmac::compute(&header_mac_key, &aad);

        let mut cursor = TlvCursor::new(&tlv_bytes);
        for item in cursor.by_ref() {
            let tlv = item.unwrap();
            if tlv.type_id == TlvType::HdrMac as u8 {
                let end = cursor.consumed_len();
                let start = end - tlv.raw().len();
                let value_offset = start + TLV_HEADER_LEN;
                tlv_bytes[value_offset..value_offset + HEADER_MAC_LEN].copy_from_slice(&mac);
                break;
            }
        }

        let ciphertext = aead::seal(&aead_key, &nonce, &aad, &plaintext).unwrap();
        let (cipher_body, tag) = ciphertext.split_at(plaintext.len());

        let mut packet = header.encode().unwrap().to_vec();
        packet.extend_from_slice(&tlv_bytes);
        packet.extend_from_slice(cipher_body);
        packet.extend_from_slice(tag);

        let parts = parse_packet(&packet).unwrap();
        parts.verify_header_mac(&header_mac_key).unwrap();
        let recovered = parts.decrypt_payload(&aead_key, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
