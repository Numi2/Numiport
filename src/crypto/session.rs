// Numan Thabit 2025 November
// crypto/session.rs - session secrets and rekey management

use std::collections::VecDeque;

use thiserror::Error;

use super::{
    aead::AeadKey,
    hkdf::{self, HkdfError},
    hmac::HeaderMacKey,
    nonce::{self, Direction, SessionId},
};

#[derive(Debug)]
pub struct SessionSecrets {
    pub header_mac_key: HeaderMacKey,
    pub aead_key: AeadKey,
    pub nonce_salt: [u8; nonce::NONCE_SALT_LEN],
}

impl SessionSecrets {
    pub fn derive(
        master: &[u8],
        session_id: SessionId,
        local_peer: &[u8],
        remote_peer: &[u8],
        epoch: u64,
    ) -> Result<Self, SessionError> {
        let header_mac_key = hkdf::derive_header_mac_key(master, &[])?;
        let aead_key = hkdf::derive_aead_key(master, &[])?;
        let nonce_salt =
            nonce::derive_nonce_salt(master, session_id, local_peer, remote_peer, epoch)?;
        Ok(Self {
            header_mac_key,
            aead_key,
            nonce_salt,
        })
    }

    pub fn derive_nonce(
        &self,
        slot: u64,
        stream: u32,
        seq: u32,
        direction: Direction,
    ) -> [u8; nonce::NONCE_LEN] {
        nonce::derive_nonce(&self.nonce_salt, slot, stream, seq, direction)
    }
}

#[derive(Debug)]
pub struct SessionManager {
    session_id: SessionId,
    local_peer: Vec<u8>,
    remote_peer: Vec<u8>,
    current_epoch: u64,
    current: SessionSecrets,
    scheduled: VecDeque<(u64, SessionSecrets)>,
}

impl SessionManager {
    pub fn new(
        session_id: SessionId,
        local_peer: impl AsRef<[u8]>,
        remote_peer: impl AsRef<[u8]>,
        epoch: u64,
        master: &[u8],
    ) -> Result<Self, SessionError> {
        let local = local_peer.as_ref().to_vec();
        let remote = remote_peer.as_ref().to_vec();
        let current = SessionSecrets::derive(master, session_id, &local, &remote, epoch)?;
        Ok(Self {
            session_id,
            local_peer: local,
            remote_peer: remote,
            current_epoch: epoch,
            current,
            scheduled: VecDeque::new(),
        })
    }

    pub fn current(&self) -> (&SessionSecrets, u64) {
        (&self.current, self.current_epoch)
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn schedule_rekey(&mut self, epoch: u64, master: &[u8]) -> Result<(), SessionError> {
        if epoch <= self.current_epoch {
            return Err(SessionError::InvalidEpoch(epoch));
        }
        if self.scheduled.iter().any(|(e, _)| *e == epoch) {
            return Err(SessionError::AlreadyScheduled(epoch));
        }
        let secrets = SessionSecrets::derive(
            master,
            self.session_id,
            &self.local_peer,
            &self.remote_peer,
            epoch,
        )?;
        self.scheduled.push_back((epoch, secrets));
        self.scheduled.make_contiguous().sort_by_key(|(e, _)| *e);
        Ok(())
    }

    pub fn rotate(&mut self, epoch: u64) -> Result<bool, SessionError> {
        if let Some(position) = self
            .scheduled
            .iter()
            .position(|(scheduled_epoch, _)| *scheduled_epoch <= epoch)
        {
            let (next_epoch, secrets) = self.scheduled.remove(position).unwrap();
            self.current = secrets;
            self.current_epoch = next_epoch;
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("hkdf error: {0}")]
    Hkdf(#[from] HkdfError),
    #[error("invalid epoch {0}")]
    InvalidEpoch(u64),
    #[error("epoch {0} already scheduled")]
    AlreadyScheduled(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::nonce::SessionStore;

    #[test]
    fn manager_rotates_on_schedule() {
        let session_id = SessionId::random();
        let master_current = [0x11u8; 32];
        let master_next = [0x22u8; 32];
        let mut manager = SessionManager::new(session_id, b"local", b"remote", 1, &master_current)
            .expect("manager");

        let current_nonce = manager.current().0.derive_nonce(1, 0, 0, Direction::Send);

        manager
            .schedule_rekey(2, &master_next)
            .expect("schedule rekey");
        assert!(manager.rotate(2).expect("rotate"));

        let new_nonce = manager.current().0.derive_nonce(1, 0, 0, Direction::Send);

        assert_ne!(current_nonce, new_nonce);
    }

    #[test]
    fn session_store_round_trip() {
        let path = {
            let mut p = std::env::temp_dir();
            p.push(format!("session-store-{}.bin", rand::random::<u64>()));
            p
        };
        let store = SessionStore::new(&path);
        let id1 = store.load_or_create().expect("create");
        let id2 = store.load().expect("load").expect("id");
        assert_eq!(id1, id2);
        std::fs::remove_file(&path).ok();
    }
}
