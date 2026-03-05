use std::net::IpAddr;
use std::time::Duration;
use sha2::{Digest, Sha256};
use argon2::{Argon2, Algorithm, Version, Params};
use hmac::{Hmac, Mac};
use rand::RngCore;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use constant_time_eq::constant_time_eq;

pub mod storage;
use storage::{StorageBackend, MemoryStorage};
#[cfg(feature = "redis")]
use storage::RedisStorage;

// ──────────────────────────────────────────────────────────────────────────────
// Argon2id parameters — must stay in sync with client-js and all other servers
// ──────────────────────────────────────────────────────────────────────────────
const ARGON2_MEMORY_COST: u32 = 19456; // KiB — 19 MiB, GPU-hostile
const ARGON2_TIME_COST: u32 = 1;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_HASH_LEN: usize = 32;

/// Maximum decoded nonce length. Client uses 32 bytes; cap at 64 to guard
/// against oversized-nonce Argon2 DoS attacks (SEC-3).
const NONCE_MAX_BYTES: usize = 64;

// ──────────────────────────────────────────────────────────────────────────────
// Domain errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Error, Debug, PartialEq, Eq)]
pub enum POWCaptchaError {
    #[error("Challenge not found or expired")]
    ChallengeNotFoundOrExpired,
    #[error("Difficulty mismatch")]
    DifficultyMismatch,
    #[error("Invalid Proof of Work")]
    InvalidProofOfWork,
    #[error("Challenge already active")]
    ChallengeAlreadyActive,
    #[error("Server busy, try again later")]
    ServerBusy,
}

// ──────────────────────────────────────────────────────────────────────────────
// Wire-format types
// ──────────────────────────────────────────────────────────────────────────────

/// Response returned by GET /challenge.
#[derive(Clone, Serialize, Deserialize)]
pub struct CaptchaResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub req_id: String,
}

/// Request body accepted by POST /verify.
#[derive(Clone, Serialize, Deserialize)]
pub struct CaptchaValidatedPOW {
    pub req_id: String,
    pub challenge: String,
    pub timestamp: String,
    pub difficulty: u32,
    pub nonce: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Server
// ──────────────────────────────────────────────────────────────────────────────

pub struct POWCaptchaServer {
    storage: StorageBackend,
    default_difficulty: u32,
    validity_seconds: i64,
    enable_fingerprint: bool,
    request_minimum_delay: Option<f64>,
    cookie_ttl: i64,
    server_secret: Vec<u8>,
    max_active_challenges: usize,
}

impl POWCaptchaServer {
    pub async fn new(
        default_difficulty: u32,
        validity_seconds: i64,
        enable_fingerprint: bool,
        request_minimum_delay: Option<f64>,
        cookie_ttl: i64,
    ) -> Self {
        let mut secret = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut secret);

        let max_active_challenges: usize = 10000;

        let storage = if let Ok(redis_url) = std::env::var("POW_REDIS_URL") {
            #[cfg(feature = "redis")]{
                StorageBackend::Redis(
                    RedisStorage::new(&redis_url, max_active_challenges)
                        .await
                        .expect("Failed to connect to Redis"),
                )
            }
            #[cfg(not(feature = "redis"))]{
                let _ = redis_url;
                eprintln!("[powchallenge] POW_REDIS_URL is set but the \"redis\" feature is not enabled. Falling back to MemoryStorage.");
                StorageBackend::Memory(MemoryStorage::new(max_active_challenges))
            }
        } else {
            StorageBackend::Memory(MemoryStorage::new(max_active_challenges))
        };

        Self {
            storage,
            default_difficulty,
            validity_seconds,
            enable_fingerprint,
            request_minimum_delay,
            cookie_ttl,
            server_secret: secret,
            max_active_challenges,
        }
    }

    /// Update the cap on simultaneous in-flight challenges.
    /// Propagates to the concrete storage backend (SEC-6).
    pub async fn set_max_active_challenges(&mut self, max: usize) {
        self.max_active_challenges = max;
        self.storage.set_max_challenges(max).await;
    }

    // ── Clearance token ──────────────────────────────────────────────────────

    fn generate_client_hash(&self, ip: IpAddr, user_agent: &str, fingerprint: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", ip, user_agent, fingerprint).as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn generate_clearance_token(&self, ip: IpAddr, user_agent: &str, fingerprint: &str) -> String {
        let exp = Utc::now().timestamp() + self.cookie_ttl;
        let client_hash = self.generate_client_hash(ip, user_agent, fingerprint);
        let payload = format!("{}:{}", exp, client_hash);

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.server_secret)
            .expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        format!("{}:{}", payload, signature)
    }

    pub fn validate_clearance_token(&self, token: &str, ip: IpAddr, user_agent: &str, fingerprint: &str) -> bool {
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 3 { return false; }

        let (exp_str, hash_str, sig_str) = (parts[0], parts[1], parts[2]);
        let exp = match exp_str.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        if Utc::now().timestamp() > exp { return false; }

        let expected_hash = self.generate_client_hash(ip, user_agent, fingerprint);
        if !constant_time_eq(expected_hash.as_bytes(), hash_str.as_bytes()) { return false; }

        let payload = format!("{}:{}", exp_str, hash_str);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.server_secret)
            .expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());
        constant_time_eq(expected_sig.as_bytes(), sig_str.as_bytes())
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn b64_encode(b: &[u8]) -> String {
        BASE64.encode(b)
    }

    fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64.decode(s)
    }

    /// Return the /24 (IPv4) or /48 (IPv6) subnet prefix, after unwrapping any
    /// IPv4-mapped IPv6 addresses (SEC-5).
    fn get_subnet_prefix(ip: IpAddr) -> String {
        // std::net::IpAddr already normalises IPv4-mapped IPv6 when parsed from
        // a string — so we can match directly on the enum variant.
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None     => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}", o[0], o[1], o[2])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}", s[0], s[1], s[2])
            }
        }
    }

    fn validate_pow_hash(h: &[u8], difficulty_bits: u32) -> bool {
        for i in 0..ARGON2_HASH_LEN {
            let bits_to_check = std::cmp::max(0, std::cmp::min(8, difficulty_bits as i32 - i as i32 * 8));
            if bits_to_check == 0 { break; }
            let mask = ((0xFF_u32 << (8 - bits_to_check)) & 0xFF) as u8;
            if (h[i] & mask) != 0 { return false; }
        }
        true
    }

    // ── Core API ─────────────────────────────────────────────────────────────

    pub async fn get_challenge(
        &self,
        client_ip: IpAddr,
        fingerprint: Option<String>,
    ) -> Result<CaptchaResponse, POWCaptchaError> {
        let now = Utc::now();
        let ip_str = client_ip.to_string();

        if self.storage.is_ip_active(&ip_str).await {
            return Err(POWCaptchaError::ChallengeAlreadyActive);
        }
        if self.storage.count_challenges().await >= self.max_active_challenges {
            return Err(POWCaptchaError::ServerBusy);
        }

        let mut dynamic_difficulty = self.default_difficulty;
        let subnet_prefix = Self::get_subnet_prefix(client_ip);
        dynamic_difficulty += self.storage.get_subnet_history(&subnet_prefix).await / 5;

        if self.enable_fingerprint {
            if let Some(ref fp) = fingerprint {
                dynamic_difficulty += self.storage.get_fingerprint_history(fp).await / 5;
            }
        }

        let recent = self.storage.get_recent_global_solves_count(60).await;
        if recent > 50 {
            dynamic_difficulty += ((recent - 50) / 10) as u32;
        }

        let mut hasher = Sha256::new();
        hasher.update(ip_str.as_bytes());
        hasher.update(&self.server_secret);
        let ip_salt = hasher.finalize();

        let mut challenge_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_bytes[0..16]);
        challenge_bytes[16..32].copy_from_slice(&ip_salt[0..16]);

        let req_id = Uuid::now_v7().to_string();

        self.storage
            .add_challenge(&req_id, &challenge_bytes, &ip_str, dynamic_difficulty, now, self.validity_seconds)
            .await
            .map_err(|_| POWCaptchaError::ServerBusy)?;

        Ok(CaptchaResponse {
            challenge: Self::b64_encode(&challenge_bytes),
            difficulty: dynamic_difficulty,
            req_id,
        })
    }

    pub async fn verify_pow(
        &self,
        request: CaptchaValidatedPOW,
        client_ip: IpAddr,
        fingerprint: Option<String>,
    ) -> Result<bool, POWCaptchaError> {
        let query_start = Utc::now();
        let ip_str = client_ip.to_string();

        // SEC-3: pre-check the base64 string length BEFORE consuming the challenge.
        // 64 bytes encodes to exactly 88 base64 chars. Any longer string would decode to
        // >64 bytes. Rejecting here means the challenge survives an oversized-nonce attack.
        // (64 bytes * 4 / 3, rounded up to next multiple of 4 = 88)
        const NONCE_MAX_B64_LEN: usize = 88;
        if request.nonce.len() > NONCE_MAX_B64_LEN {
            return Err(POWCaptchaError::InvalidProofOfWork);
        }

        let state = self.storage
            .get_and_delete_challenge(&request.req_id)
            .await
            .ok_or(POWCaptchaError::ChallengeNotFoundOrExpired)?;

        if state.ip != ip_str {
            return Err(POWCaptchaError::ChallengeNotFoundOrExpired);
        }

        if let Ok(ts) = state.timestamp.parse::<DateTime<Utc>>() {
            if (Utc::now() - ts).num_seconds() > self.validity_seconds {
                return Err(POWCaptchaError::ChallengeNotFoundOrExpired);
            }
        } else {
            return Err(POWCaptchaError::ChallengeNotFoundOrExpired);
        }

        if request.difficulty != state.difficulty {
            return Err(POWCaptchaError::DifficultyMismatch);
        }

        let challenge_bytes = Self::b64_decode(&request.challenge)
            .map_err(|_| POWCaptchaError::InvalidProofOfWork)?;
        let nonce_bytes = Self::b64_decode(&request.nonce)
            .map_err(|_| POWCaptchaError::InvalidProofOfWork)?;

        // SEC-3: decoded-length guard (belt-and-suspenders after the b64 check above)
        if nonce_bytes.len() > NONCE_MAX_BYTES {
            return Err(POWCaptchaError::InvalidProofOfWork);
        }

        let expected_challenge = hex::decode(&state.challenge)
            .map_err(|_| POWCaptchaError::InvalidProofOfWork)?;

        if challenge_bytes.len() != expected_challenge.len()
            || !constant_time_eq(&challenge_bytes, &expected_challenge)
        {
            return Err(POWCaptchaError::InvalidProofOfWork);
        }

        let params = Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(ARGON2_HASH_LEN))
            .map_err(|_| POWCaptchaError::InvalidProofOfWork)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut computed_hash = vec![0u8; ARGON2_HASH_LEN];
        argon2
            .hash_password_into(&nonce_bytes, &challenge_bytes, &mut computed_hash)
            .map_err(|_| POWCaptchaError::InvalidProofOfWork)?;

        if !Self::validate_pow_hash(&computed_hash, state.difficulty) {
            return Err(POWCaptchaError::InvalidProofOfWork);
        }

        self.storage.add_global_solve(Utc::now()).await;
        let subnet_prefix = Self::get_subnet_prefix(client_ip);
        self.storage.increment_subnet_history(&subnet_prefix).await;
        if self.enable_fingerprint {
            if let Some(fp) = fingerprint {
                self.storage.increment_fingerprint_history(&fp).await;
            }
        }

        if let Some(delay) = self.request_minimum_delay {
            let elapsed = (Utc::now() - query_start)
                .to_std()
                .unwrap_or(Duration::ZERO)
                .as_secs_f64();
            if elapsed < delay {
                tokio::time::sleep(Duration::from_secs_f64(delay - elapsed)).await;
            }
        }

        Ok(true)
    }
}
