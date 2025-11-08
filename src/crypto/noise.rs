// Numan Thabit 2026
// crypto/noise.rs - Noise IKpsk2 handshake via 'snow'
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use thiserror::Error;

/// Default Noise pattern and primitives used by Numiport.
const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Clone)]
pub struct NoiseConfig {
    pub local_static: [u8; 32],
    pub remote_static: Option<[u8; 32]>,
    pub prologue: Vec<u8>,
    pub psk: [u8; 32],
}

impl NoiseConfig {
    pub fn new(local_static: [u8; 32], remote_static: Option<[u8; 32]>, psk: [u8; 32]) -> Self {
        Self {
            local_static,
            remote_static,
            prologue: b"numiport-noise".to_vec(),
            psk,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("missing remote static key for initiator handshake")]
    MissingRemoteStatic,
    #[error("handshake already completed")]
    AlreadyCompleted,
    #[error("handshake not yet complete")]
    Incomplete,
    #[error("noise error: {0}")]
    Snow(#[from] snow::Error),
}

/// Wrapper around a Noise IKpsk2 handshake.
#[derive(Debug)]
pub struct NoiseHandshake {
    role: NoiseRole,
    state: Option<HandshakeState>,
}

impl NoiseHandshake {
    pub fn new(role: NoiseRole, config: NoiseConfig) -> Result<Self, NoiseError> {
        let params: NoiseParams = NOISE_PATTERN.parse().expect("valid noise pattern");
        let mut builder = Builder::new(params)
            .local_private_key(&config.local_static)
            .psk(0, &config.psk)
            .prologue(&config.prologue);

        if let Some(remote) = config.remote_static {
            builder = builder.remote_public_key(&remote);
        } else if role == NoiseRole::Initiator {
            return Err(NoiseError::MissingRemoteStatic);
        }

        let state = match role {
            NoiseRole::Initiator => builder.build_initiator()?,
            NoiseRole::Responder => builder.build_responder()?,
        };

        Ok(Self {
            role,
            state: Some(state),
        })
    }

    pub fn role(&self) -> NoiseRole {
        self.role
    }

    pub fn is_complete(&self) -> bool {
        self.state
            .as_ref()
            .map(|state| state.is_handshake_finished())
            .unwrap_or(true)
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let state = self.state.as_mut().ok_or(NoiseError::AlreadyCompleted)?;
        let mut buf = vec![0u8; payload.len() + 256];
        let len = state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let state = self.state.as_mut().ok_or(NoiseError::AlreadyCompleted)?;
        let mut buf = vec![0u8; message.len() + 256];
        let len = state.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn into_session(mut self) -> Result<NoiseSession, NoiseError> {
        let state = self.state.take().ok_or(NoiseError::AlreadyCompleted)?;
        if !state.is_handshake_finished() {
            return Err(NoiseError::Incomplete);
        }
        let transport = state.into_transport_mode()?;
        Ok(NoiseSession { transport })
    }
}

/// Transport session derived from a completed Noise handshake.
#[derive(Debug)]
pub struct NoiseSession {
    transport: TransportState,
}

impl NoiseSession {
    pub fn export_master(&mut self) -> Result<[u8; 32], NoiseError> {
        let mut key = [0u8; 32];
        self.transport
            .export_keying_material(b"numiport/master", &[], &mut key)
            .map_err(NoiseError::from)?;
        Ok(key)
    }

    pub fn handshake_hash(&self) -> Vec<u8> {
        self.transport.get_handshake_hash().to_vec()
    }

    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.transport.get_remote_static().map(|key| key.to_vec())
    }

    pub fn into_transport_state(self) -> TransportState {
        self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn completes_ikpsk2_handshake() {
        let prologue = b"test-prologue".to_vec();
        let initiator_static = random_key();
        let responder_static = random_key();
        let psk = random_key();

        let mut initiator = NoiseHandshake::new(
            NoiseRole::Initiator,
            NoiseConfig {
                local_static: initiator_static,
                remote_static: Some(responder_static),
                prologue: prologue.clone(),
                psk,
            },
        )
        .expect("initiator");

        let mut responder = NoiseHandshake::new(
            NoiseRole::Responder,
            NoiseConfig {
                local_static: responder_static,
                remote_static: None,
                prologue,
                psk,
            },
        )
        .expect("responder");

        let msg1 = initiator.write_message(&[]).expect("msg1");
        let _ = responder.read_message(&msg1).expect("recv1");
        let msg2 = responder.write_message(&[]).expect("msg2");
        let _ = initiator.read_message(&msg2).expect("recv2");

        assert!(initiator.is_complete());
        assert!(responder.is_complete());

        let mut init_session = initiator.into_session().expect("initiator session");
        let mut resp_session = responder.into_session().expect("responder session");

        let init_master = init_session.export_master().expect("init master");
        let resp_master = resp_session.export_master().expect("resp master");

        assert_eq!(init_master, resp_master);
    }
}

