// Numan Thabit 2025
// crypto/nonce.rs - session-salted nonce derivation

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use blake3::Hasher;
use rand::RngCore;
use thiserror::Error;

use super::hkdf;

pub const NONCE_LEN: usize = 24;
pub const NONCE_SALT_LEN: usize = 32;
const NONCE_SALT_LABEL: &[u8] = b"nonce-salt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    pub const fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

impl Direction {
    const fn to_byte(self) -> u8 {
        match self {
            Direction::Send => 0,
            Direction::Receive => 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid session id length: {0}")]
    InvalidLength(usize),
}

pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_create(&self) -> Result<SessionId, SessionStoreError> {
        match self.load()? {
            Some(id) => Ok(id),
            None => {
                let id = SessionId::random();
                self.store(id)?;
                Ok(id)
            }
        }
    }

    pub fn load(&self) -> Result<Option<SessionId>, SessionStoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                if bytes.len() != 16 {
                    return Err(SessionStoreError::InvalidLength(bytes.len()));
                }
                let mut array = [0u8; 16];
                array.copy_from_slice(&bytes);
                Ok(Some(SessionId::from_bytes(array)))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(SessionStoreError::Io(err)),
        }
    }

    pub fn store(&self, session_id: SessionId) -> Result<(), SessionStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, session_id.to_bytes())?;
        Ok(())
    }
}

pub fn derive_nonce_salt(
    master: &[u8],
    session_id: SessionId,
    local_peer: &[u8],
    remote_peer: &[u8],
    epoch: u64,
) -> Result<[u8; NONCE_SALT_LEN], hkdf::HkdfError> {
    let mut info =
        Vec::with_capacity(NONCE_SALT_LABEL.len() + 16 + local_peer.len() + remote_peer.len() + 8);
    info.extend_from_slice(NONCE_SALT_LABEL);
    info.extend_from_slice(&session_id.to_bytes());
    info.extend_from_slice(local_peer);
    info.extend_from_slice(remote_peer);
    info.extend_from_slice(&epoch.to_be_bytes());

    let salt_bytes = hkdf::derive(master, &[], &info, NONCE_SALT_LEN)?;
    let mut salt = [0u8; NONCE_SALT_LEN];
    salt.copy_from_slice(&salt_bytes);
    Ok(salt)
}

pub fn derive_nonce(
    salt: &[u8; NONCE_SALT_LEN],
    slot: u64,
    stream: u32,
    seq: u32,
    direction: Direction,
) -> [u8; NONCE_LEN] {
    let mut hasher = Hasher::new_keyed(salt);
    hasher.update(&slot.to_be_bytes());
    hasher.update(&stream.to_be_bytes());
    hasher.update(&seq.to_be_bytes());
    hasher.update(&[direction.to_byte()]);
    let output = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&output.as_bytes()[..NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn temp_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("numiport-session-{}.bin", rand::random::<u64>()));
        path
    }

    #[test]
    fn persist_restore_session_id() {
        let path = temp_path();
        let store = SessionStore::new(&path);
        let first = store.load_or_create().expect("create session id");
        let second = store.load_or_create().expect("load session id");
        assert_eq!(first, second);
        fs::remove_file(path).ok();
    }

    proptest! {
        #[test]
        fn nonce_uniqueness(
            master in prop::array::uniform32(any::<u8>()),
            session_bytes in prop::array::uniform16(any::<u8>()),
            epoch in any::<u64>(),
            contexts in prop::collection::vec((any::<u64>(), any::<u32>(), any::<u32>(), any::<bool>()), 1..50)
        ) {
            let session_id = SessionId::from_bytes(session_bytes);
            let salt = derive_nonce_salt(&master, session_id, b"local", b"remote", epoch).expect("salt");

            let mut seen = HashSet::new();
            for (slot, stream, seq, dir_flag) in contexts {
                let direction = if dir_flag { Direction::Send } else { Direction::Receive };
                let nonce = derive_nonce(&salt, slot, stream, seq, direction);
                assert!(seen.insert(nonce), "duplicate nonce for parameters");
            }
        }
    }
}
