// Cryptographic context handling frame sealing and opening.
// Numan Thabit 2025
use super::{
    aead::{self, Nonce as AeadNonce},
    hmac,
    nonce::Direction,
    session::SessionManager,
};

use crate::wire::{self, NumiHdr, PacketParts, TlvBuilder, TlvCursor, TlvType, WireError};

/// Sealed frame components returned by [`CryptoContext::seal`].
#[derive(Debug, Clone)]
pub struct SealedFrame {
    pub tlv_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Maintains the active session keys and provides helpers for record protection.
#[derive(Debug)]
pub struct CryptoContext {
    session: SessionManager,
}

impl CryptoContext {
    /// Creates a context from an established session manager.
    pub fn from_session(session: SessionManager) -> Self {
        Self { session }
    }

    /// Returns the underlying session manager.
    pub fn session(&self) -> &SessionManager {
        &self.session
    }

    /// Returns a mutable reference to the session manager (used for rotation).
    pub fn session_mut(&mut self) -> &mut SessionManager {
        &mut self.session
    }

    /// Encrypts `payload`, returning TLVs augmented with HDR_MAC and the ciphertext+tag.
    pub fn seal(
        &mut self,
        slot: u64,
        stream: u32,
        seq: u32,
        header: &NumiHdr,
        base_tlvs: &[u8],
        payload: &[u8],
    ) -> Result<SealedFrame, WireError> {
        let (secrets, _) = self.session.current();
        let nonce_bytes = secrets.derive_nonce(slot, stream, seq, Direction::Send);
        let nonce = AeadNonce::xchacha(nonce_bytes);

        let aad = wire::build_aad(header, base_tlvs)?;
        let mac = hmac::compute(&secrets.header_mac_key, &aad);

        let mut final_builder = TlvBuilder::new();
        let mut cursor = TlvCursor::new(base_tlvs);
        for item in cursor.by_ref() {
            let tlv = item?;
            if tlv.type_id == TlvType::End as u8 {
                break;
            }
            final_builder.push_raw(tlv.type_id, tlv.value)?;
        }
        final_builder.push(TlvType::HdrMac, &mac)?;
        let tlv_bytes = final_builder.finish()?;

        let ciphertext = aead::seal(&secrets.aead_key, &nonce, &aad, payload)?;

        Ok(SealedFrame {
            tlv_bytes,
            ciphertext,
        })
    }

    /// Decrypts and authenticates the payload contained in `parts`.
    pub fn open(&mut self, parts: &PacketParts<'_>) -> Result<Vec<u8>, WireError> {
        let (secrets, _) = self.session.current();
        parts.verify_header_mac(&secrets.header_mac_key)?;
        let nonce_bytes = secrets.derive_nonce(
            parts.header.slot,
            parts.header.stream,
            parts.header.seq,
            Direction::Receive,
        );
        let nonce = AeadNonce::xchacha(nonce_bytes);
        parts.decrypt_payload(&secrets.aead_key, &nonce)
    }
}
