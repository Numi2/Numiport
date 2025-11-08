// Header MAC based on HMAC-SHA256 truncated to 16 bytes.
// Numan Thabit 2025 its friday nov 7 and i didnt sleep my night got truncated also

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Length of the truncated header MAC tag.
pub const HEADER_MAC_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Wrapper for 256-bit header MAC keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMacKey(pub [u8; 32]);

impl HeaderMacKey {
    /// Creates a new key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Errors returned by the header MAC functions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderMacError {
    /// The provided tag length does not match the truncated size.
    #[error("invalid header mac length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected tag length.
        expected: usize,
        /// Actual tag length supplied by the caller.
        actual: usize,
    },
    /// Computed MAC did not match the provided tag.
    #[error("header mac verification failed")]
    VerificationFailed,
}

/// Computes the truncated header MAC for the given message.
#[must_use]
pub fn compute(key: &HeaderMacKey, message: &[u8]) -> [u8; HEADER_MAC_LEN] {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("hmac key length should be valid");
    mac.update(message);
    let full_tag = mac.finalize().into_bytes();
    let mut tag = [0u8; HEADER_MAC_LEN];
    tag.copy_from_slice(&full_tag[..HEADER_MAC_LEN]);
    tag
}

/// Verifies a provided header MAC tag against the message.
pub fn verify(key: &HeaderMacKey, message: &[u8], tag: &[u8]) -> Result<(), HeaderMacError> {
    if tag.len() != HEADER_MAC_LEN {
        return Err(HeaderMacError::InvalidLength {
            expected: HEADER_MAC_LEN,
            actual: tag.len(),
        });
    }

    let expected = compute(key, message);
    if expected.as_slice().ct_eq(tag).into() {
        Ok(())
    } else {
        Err(HeaderMacError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_and_verifies() {
        let key = HeaderMacKey::new([7u8; 32]);
        let message = b"numiport-header";
        let tag = compute(&key, message);
        assert_eq!(tag.len(), HEADER_MAC_LEN);
        assert!(verify(&key, message, &tag).is_ok());
    }

    #[test]
    fn rejects_wrong_tag_length() {
        let key = HeaderMacKey::new([1u8; 32]);
        let err = verify(&key, b"test", &[0u8; 8]).unwrap_err();
        assert_eq!(
            err,
            HeaderMacError::InvalidLength {
                expected: HEADER_MAC_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn rejects_modified_tag() {
        let key = HeaderMacKey::new([2u8; 32]);
        let message = b"numiport";
        let mut tag = compute(&key, message);
        tag[0] ^= 0x01;
        assert_eq!(
            verify(&key, message, &tag),
            Err(HeaderMacError::VerificationFailed)
        );
    }
}
