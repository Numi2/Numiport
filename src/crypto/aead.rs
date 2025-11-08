// AEAD primitives for record protection.
// Numan Thabit 2025

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use thiserror::Error;

#[cfg(feature = "aes-gcm-siv")]
use aes_gcm_siv::{aead::Payload as GcmPayload, Aes256GcmSiv, Nonce as GcmNonce};

/// Authentication tag length for supported AEADs.
pub const TAG_LEN: usize = 16;

/// Nonce size for XChaCha20-Poly1305.
pub const XCHACHA20_NONCE_LEN: usize = 24;

/// Nonce size for AES-GCM-SIV.
#[cfg(feature = "aes-gcm-siv")]
pub const AES_GCM_SIV_NONCE_LEN: usize = 12;

/// AEAD algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// XChaCha20-Poly1305 (default path).
    XChaCha20Poly1305,
    /// AES-GCM-SIV (optional, feature `aes-gcm-siv`).
    #[cfg(feature = "aes-gcm-siv")]
    AesGcmSiv,
}

/// Supported AEAD key types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadKey {
    /// XChaCha20-Poly1305 key (32 bytes).
    XChaCha20Poly1305([u8; 32]),
    /// AES-GCM-SIV key (32 bytes).
    #[cfg(feature = "aes-gcm-siv")]
    AesGcmSiv([u8; 32]),
}

impl AeadKey {
    /// Constructs an XChaCha20-Poly1305 key.
    #[must_use]
    pub const fn xchacha(bytes: [u8; 32]) -> Self {
        Self::XChaCha20Poly1305(bytes)
    }

    /// Constructs an AES-GCM-SIV key.
    #[cfg(feature = "aes-gcm-siv")]
    #[must_use]
    pub const fn aes_gcm_siv(bytes: [u8; 32]) -> Self {
        Self::AesGcmSiv(bytes)
    }

    /// Returns the algorithm for this key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::XChaCha20Poly1305(_) => Algorithm::XChaCha20Poly1305,
            #[cfg(feature = "aes-gcm-siv")]
            Self::AesGcmSiv(_) => Algorithm::AesGcmSiv,
        }
    }

    /// Returns the authentication tag length for this algorithm.
    #[must_use]
    pub const fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

/// Algorithm-specific nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nonce {
    /// XChaCha20-Poly1305 nonce.
    XChaCha([u8; XCHACHA20_NONCE_LEN]),
    /// AES-GCM-SIV nonce.
    #[cfg(feature = "aes-gcm-siv")]
    AesGcmSiv([u8; AES_GCM_SIV_NONCE_LEN]),
}

impl Nonce {
    /// Constructs a nonce for XChaCha20-Poly1305.
    #[must_use]
    pub const fn xchacha(bytes: [u8; XCHACHA20_NONCE_LEN]) -> Self {
        Self::XChaCha(bytes)
    }

    /// Constructs a nonce for AES-GCM-SIV.
    #[cfg(feature = "aes-gcm-siv")]
    #[must_use]
    pub const fn aes_gcm_siv(bytes: [u8; AES_GCM_SIV_NONCE_LEN]) -> Self {
        Self::AesGcmSiv(bytes)
    }
}

/// Errors returned by AEAD helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AeadError {
    /// Nonce length did not match algorithm expectations.
    #[error("nonce length mismatch for {0:?}")]
    NonceLengthMismatch(Algorithm),
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// Decryption failed.
    #[error("decryption failed")]
    Decrypt,
}

/// Encrypts `plaintext`, returning ciphertext concatenated with the authentication tag.
pub fn seal(
    key: &AeadKey,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    match (key, nonce) {
        (AeadKey::XChaCha20Poly1305(k), Nonce::XChaCha(n)) => {
            let cipher = XChaCha20Poly1305::new(k.into());
            let mut nonce = XNonce::default();
            nonce.clone_from_slice(n);
            cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::Encrypt)
        }
        #[cfg(feature = "aes-gcm-siv")]
        (AeadKey::AesGcmSiv(k), Nonce::AesGcmSiv(n)) => {
            let cipher = Aes256GcmSiv::new(k.into());
            let mut nonce = GcmNonce::default();
            nonce.clone_from_slice(n);
            cipher
                .encrypt(
                    &nonce,
                    GcmPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::Encrypt)
        }
        #[cfg(feature = "aes-gcm-siv")]
        _ => Err(AeadError::NonceLengthMismatch(key.algorithm())),
    }
}

/// Decrypts ciphertext+tag produced by [`seal`].
pub fn open(
    key: &AeadKey,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    match (key, nonce) {
        (AeadKey::XChaCha20Poly1305(k), Nonce::XChaCha(n)) => {
            let cipher = XChaCha20Poly1305::new(k.into());
            let mut nonce = XNonce::default();
            nonce.clone_from_slice(n);
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::Decrypt)
        }
        #[cfg(feature = "aes-gcm-siv")]
        (AeadKey::AesGcmSiv(k), Nonce::AesGcmSiv(n)) => {
            let cipher = Aes256GcmSiv::new(k.into());
            let mut nonce = GcmNonce::default();
            nonce.clone_from_slice(n);
            cipher
                .decrypt(
                    &nonce,
                    GcmPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::Decrypt)
        }
        #[cfg(feature = "aes-gcm-siv")]
        _ => Err(AeadError::NonceLengthMismatch(key.algorithm())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xchacha_round_trip() {
        let key = AeadKey::xchacha([0x11; 32]);
        let nonce = Nonce::xchacha([0x22; XCHACHA20_NONCE_LEN]);
        let aad = b"slot-aad";
        let plaintext = b"hello numiport";

        let ciphertext = seal(&key, &nonce, aad, plaintext).expect("seal");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);

        let recovered = open(&key, &nonce, aad, &ciphertext).expect("open");
        assert_eq!(recovered, plaintext);
    }

    #[cfg(feature = "aes-gcm-siv")]
    #[test]
    fn aes_gcm_siv_round_trip() {
        let key = AeadKey::aes_gcm_siv([0x33; 32]);
        let nonce = Nonce::aes_gcm_siv([0x44; AES_GCM_SIV_NONCE_LEN]);
        let aad = b"slot-aad";
        let plaintext = b"guard delta";

        let ciphertext = seal(&key, &nonce, aad, plaintext).expect("seal");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);

        let recovered = open(&key, &nonce, aad, &ciphertext).expect("open");
        assert_eq!(recovered, plaintext);
    }

    #[cfg(feature = "aes-gcm-siv")]
    #[test]
    fn rejects_nonce_mismatch() {
        let key = AeadKey::xchacha([9; 32]);
        let nonce = Nonce::aes_gcm_siv([1; AES_GCM_SIV_NONCE_LEN]);
        let aad = b"a";
        let plaintext = b"b";

        assert_eq!(
            seal(&key, &nonce, aad, plaintext),
            Err(AeadError::NonceLengthMismatch(Algorithm::XChaCha20Poly1305))
        );
    }
}
