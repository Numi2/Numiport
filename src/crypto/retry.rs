use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type CookieHmac = Hmac<Sha256>;

const TIMESTAMP_LEN: usize = 8;
const TAG_LEN: usize = 16;
const COOKIE_LEN: usize = TIMESTAMP_LEN + TAG_LEN;

#[derive(Debug, Clone)]
pub struct RetryCookieManager {
    secret: [u8; 32],
    ttl: Duration,
}

impl RetryCookieManager {
    pub fn new(ttl: Duration) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self { secret, ttl }
    }

    pub fn encode(&self, context: &[u8], slot: u64, stream: u32, now: SystemTime) -> Vec<u8> {
        let ts = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut mac = CookieHmac::new_from_slice(&self.secret).expect("valid hmac key");
        mac.update(context);
        mac.update(&slot.to_be_bytes());
        mac.update(&stream.to_be_bytes());
        mac.update(&ts.to_be_bytes());
        let tag = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(COOKIE_LEN);
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&tag[..TAG_LEN]);
        out
    }

    pub fn verify(
        &self,
        context: &[u8],
        slot: u64,
        stream: u32,
        cookie: &[u8],
        now: SystemTime,
    ) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let ts = u64::from_be_bytes(
            cookie[..TIMESTAMP_LEN]
                .try_into()
                .expect("timestamp length mismatch"),
        );
        let ts_duration = Duration::from_secs(ts);
        let now_duration = match now.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(_) => return false,
        };
        if now_duration < ts_duration {
            return false;
        }
        if now_duration - ts_duration > self.ttl {
            return false;
        }

        let mut mac = CookieHmac::new_from_slice(&self.secret).expect("valid hmac key");
        mac.update(context);
        mac.update(&slot.to_be_bytes());
        mac.update(&stream.to_be_bytes());
        mac.update(&ts.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        tag[..TAG_LEN]
            .ct_eq(&cookie[TIMESTAMP_LEN..TIMESTAMP_LEN + TAG_LEN])
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trip() {
        let manager = RetryCookieManager::new(Duration::from_secs(3));
        let context = b"peer-ctx";
        let now = SystemTime::now();
        let cookie = manager.encode(context, 42, 7, now);
        assert!(manager.verify(context, 42, 7, &cookie, now));
        assert!(!manager.verify(context, 43, 7, &cookie, now));
    }
}
