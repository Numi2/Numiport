// HKDF-based key schedule helpers.
// Numan Thabit 2025

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use super::{aead::AeadKey, hmac::HeaderMacKey};

/// Default info label for deriving header MAC keys.
pub const INFO_HEADER_MAC: &[u8] = b"numiport/hmac";

/// Default info label for deriving AEAD keys.
pub const INFO_AEAD_KEY: &[u8] = b"numiport/aead";

/// HKDF errors surfaced by helper functions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HkdfError {
    /// Requested output was too long for the underlying HKDF.
    #[error("hkdf output length invalid")]
    InvalidLength,
}

/// Derives keying material of the requested length.
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, HkdfError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|_| HkdfError::InvalidLength)?;
    Ok(okm)
}

/// Derives a [`HeaderMacKey`] using the default info label.
pub fn derive_header_mac_key(ikm: &[u8], salt: &[u8]) -> Result<HeaderMacKey, HkdfError> {
    let material = derive(ikm, salt, INFO_HEADER_MAC, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&material);
    Ok(HeaderMacKey::new(key))
}

/// Derives an [`AeadKey`] using the default info label.
pub fn derive_aead_key(ikm: &[u8], salt: &[u8]) -> Result<AeadKey, HkdfError> {
    let material = derive(ikm, salt, INFO_AEAD_KEY, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&material);
    Ok(AeadKey::xchacha(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_key_derivation() {
        let ikm = b"master secret";
        let salt = b"numi";
        let header_key = derive_header_mac_key(ikm, salt).expect("header key");
        let aead_key = derive_aead_key(ikm, salt).expect("aead key");

        // Calling again should produce identical keys.
        assert_eq!(header_key, derive_header_mac_key(ikm, salt).unwrap());
        assert_eq!(aead_key, derive_aead_key(ikm, salt).unwrap());
    }
}
