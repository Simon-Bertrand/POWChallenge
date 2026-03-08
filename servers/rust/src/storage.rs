use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use parking_lot::Mutex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Storage-specific error type (replaces bare `String` errors)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Server busy")]
    Capacity,
    #[cfg(feature = "redis")]
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
}

// ──────────────────────────────────────────────────────────────────────────────
// Serialised challenge state (stored in both Memory and Redis)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CaptchaRequestState {
    pub challenge: String, // hex-encoded raw bytes
    pub ip: String,
    pub timestamp: String, // RFC-3339
    pub difficulty: u32,
}

// ──────────────────────────────────────────────────────────────────────────────
// StorageBackend — enum dispatch (avoids dynamic dispatch overhead)
// ──────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn store_challenge(
        &self,
        req_id: &str,
        challenge_bytes: &[u8],
        ip: &str,
        difficulty: u32,
        timestamp: DateTime<Utc>,
        validity_seconds: i64,
    ) -> Result<(), StorageError>;

    async fn fetch_challenge(&self, req_id: &str) -> Option<CaptchaRequestState>;
    async fn delete_challenge(&self, req_id: &str) -> bool;

    async fn count_challenges(&self) -> usize;
    async fn is_ip_active(&self, ip: &str) -> bool;
    async fn increment_subnet_history(&self, subnet: &str);
    async fn get_subnet_history(&self, subnet: &str) -> u32;
    async fn increment_fingerprint_history(&self, fingerprint: &str);
    async fn get_fingerprint_history(&self, fingerprint: &str) -> u32;
    async fn add_global_solve(&self, timestamp: DateTime<Utc>);
    async fn get_recent_global_solves_count(&self, window_seconds: i64) -> usize;
    async fn set_max_challenges(&mut self, max: usize);
}

// ──────────────────────────────────────────────────────────────────────────────
// In-memory implementation
// ──────────────────────────────────────────────────────────────────────────────

pub struct MemoryStorage {
    active_challenges: Arc<Mutex<HashMap<String, CaptchaRequestState>>>,
    active_ips: Arc<Mutex<HashSet<String>>>,
    fingerprint_history: Arc<Mutex<HashMap<String, u32>>>,
    subnet_history: Arc<Mutex<HashMap<String, u32>>>,
    global_solve_history: Arc<Mutex<VecDeque<DateTime<Utc>>>>,
    pub max_challenges: usize,
}

impl MemoryStorage {
    pub fn new(max_challenges: usize) -> Self {
        Self {
            active_challenges: Arc::new(Mutex::new(HashMap::new())),
            active_ips: Arc::new(Mutex::new(HashSet::new())),
            fingerprint_history: Arc::new(Mutex::new(HashMap::new())),
            subnet_history: Arc::new(Mutex::new(HashMap::new())),
            global_solve_history: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            max_challenges,
        }
    }

    fn cleanup_expired(&self, validity_seconds: i64) {
        let now = Utc::now();
        let mut challenges = self.active_challenges.lock();
        let mut ips = self.active_ips.lock();

        let expired: Vec<String> = challenges
            .iter()
            .filter_map(|(id, state)| {
                state.timestamp.parse::<DateTime<Utc>>().ok().and_then(|ts| {
                    if (now - ts).num_seconds() > validity_seconds { Some(id.clone()) } else { None }
                })
            })
            .collect();

        for id in expired {
            if let Some(state) = challenges.remove(&id) {
                ips.remove(&state.ip);
            }
        }
    }

    pub fn count_challenges(&self) -> usize { self.active_challenges.lock().len() }

    pub fn add_challenge(
        &self,
        req_id: &str,
        challenge_bytes: &[u8],
        ip: &str,
        difficulty: u32,
        timestamp: DateTime<Utc>,
        validity_seconds: i64,
    ) -> Result<(), StorageError> {
        self.cleanup_expired(validity_seconds);
        let mut challenges = self.active_challenges.lock();
        if challenges.len() >= self.max_challenges {
            return Err(StorageError::Capacity);
        }
        challenges.insert(req_id.to_string(), CaptchaRequestState {
            challenge: hex::encode(challenge_bytes),
            ip: ip.to_string(),
            timestamp: timestamp.to_rfc3339(),
            difficulty,
        });
        self.active_ips.lock().insert(ip.to_string());
        Ok(())
    }

    fn evict_map(map: &mut HashMap<String, u32>) {
        if map.len() > 10000 {
            let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            map.clear();
            for (k, v) in entries.into_iter().take(5000) { map.insert(k, v); }
        }
    }
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl StorageBackend for RedisStorage {
    async fn store_challenge(
        &self,
        req_id: &str,
        challenge_bytes: &[u8],
        ip: &str,
        difficulty: u32,
        timestamp: DateTime<Utc>,
        validity_seconds: i64,
    ) -> Result<(), StorageError> {
        let mut con = self.con.clone();
        let state = CaptchaRequestState {
            challenge: hex::encode(challenge_bytes),
            ip: ip.to_string(),
            timestamp: timestamp.to_rfc3339(),
            difficulty,
        };
        let state_json = serde_json::to_string(&state)?;

        let mut pipe = redis::pipe();
        pipe.cmd("SETEX").arg(format!("{}req:{}", self.prefix, req_id)).arg(validity_seconds).arg(&state_json);
        pipe.cmd("SETEX").arg(format!("{}ip:{}", self.prefix, ip)).arg(validity_seconds).arg("1");
        pipe.cmd("ZADD").arg(format!("{}active_challenges_zset", self.prefix)).arg(timestamp.timestamp()).arg(req_id);
        let _: () = pipe.query_async(&mut con).await?;
        Ok(())
    }

    async fn fetch_challenge(&self, req_id: &str) -> Option<CaptchaRequestState> {
        let mut con = self.con.clone();
        let req_key = format!("{}req:{}", self.prefix, req_id);

        let raw: Option<String> = redis::cmd("GET")
            .arg(&req_key)
            .query_async(&mut con)
            .await
            .unwrap_or(None);

        let raw = raw?;
        serde_json::from_str(&raw).ok()
    }

    async fn delete_challenge(&self, req_id: &str) -> bool {
        let mut con = self.con.clone();
        let req_key = format!("{}req:{}", self.prefix, req_id);

        let raw: Option<String> = redis::Script::new(LUA_GET_AND_DELETE)
            .key(&req_key)
            .invoke_async(&mut con)
            .await
            .unwrap_or(None);

        if let Some(raw_str) = raw {
            if let Ok(state) = serde_json::from_str::<CaptchaRequestState>(&raw_str) {
                let mut pipe = redis::pipe();
                pipe.cmd("DEL").arg(format!("{}ip:{}", self.prefix, state.ip));
                pipe.cmd("ZREM").arg(format!("{}active_challenges_zset", self.prefix)).arg(req_id);
                let _: () = pipe.query_async(&mut con).await.unwrap_or(());
                return true;
            }
        }
        false
    }

    async fn count_challenges(&self) -> usize {
        let mut con = self.con.clone();
        let now = Utc::now().timestamp();
        let key = format!("{}active_challenges_zset", self.prefix);
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&key).arg("-inf").arg(now - 300)
            .query_async(&mut con).await.unwrap_or(());
        redis::cmd("ZCARD").arg(&key).query_async(&mut con).await.unwrap_or(0)
    }

    async fn is_ip_active(&self, ip: &str) -> bool {
        let mut con = self.con.clone();
        redis::cmd("EXISTS")
            .arg(format!("{}ip:{}", self.prefix, ip))
            .query_async(&mut con).await.unwrap_or(false)
    }

    async fn increment_subnet_history(&self, subnet: &str) {
        let mut con = self.con.clone();
        let key = format!("{}subnet:{}", self.prefix, subnet);
        let _: () = redis::cmd("INCR").arg(&key).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("EXPIRE").arg(&key).arg(86400).query_async(&mut con).await.unwrap_or(());
    }

    async fn get_subnet_history(&self, subnet: &str) -> u32 {
        let mut con = self.con.clone();
        redis::cmd("GET")
            .arg(format!("{}subnet:{}", self.prefix, subnet))
            .query_async(&mut con).await.unwrap_or(0)
    }

    async fn increment_fingerprint_history(&self, fingerprint: &str) {
        let mut con = self.con.clone();
        let key = format!("{}fingerprint:{}", self.prefix, fingerprint);
        let _: () = redis::cmd("INCR").arg(&key).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("EXPIRE").arg(&key).arg(86400).query_async(&mut con).await.unwrap_or(());
    }

    async fn get_fingerprint_history(&self, fingerprint: &str) -> u32 {
        let mut con = self.con.clone();
        redis::cmd("GET")
            .arg(format!("{}fingerprint:{}", self.prefix, fingerprint))
            .query_async(&mut con).await.unwrap_or(0)
    }

    async fn add_global_solve(&self, timestamp: DateTime<Utc>) {
        let mut con = self.con.clone();
        let key = format!("{}global_solves", self.prefix);
        let score = timestamp.timestamp();
        let member = format!("{}-{}", score, rand::random::<u32>());
        let _: () = redis::cmd("ZADD").arg(&key).arg(score).arg(&member).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("ZREMRANGEBYSCORE").arg(&key).arg("-inf").arg(score - 60).query_async(&mut con).await.unwrap_or(());
    }

    async fn get_recent_global_solves_count(&self, window_seconds: i64) -> usize {
        let mut con = self.con.clone();
        let key = format!("{}global_solves", self.prefix);
        let now = Utc::now().timestamp();
        redis::cmd("ZCOUNT").arg(&key).arg(now - window_seconds).arg("+inf").query_async(&mut con).await.unwrap_or(0)
    }

    async fn set_max_challenges(&mut self, max: usize) {
        self.max_challenges = max;
    }
}

#[async_trait::async_trait]
impl StorageBackend for MemoryStorage {
    async fn count_challenges(&self) -> usize { self.active_challenges.lock().len() }

    async fn store_challenge(
        &self,
        req_id: &str,
        challenge_bytes: &[u8],
        ip: &str,
        difficulty: u32,
        timestamp: DateTime<Utc>,
        validity_seconds: i64,
    ) -> Result<(), StorageError> {
        self.cleanup_expired(validity_seconds);
        let mut challenges = self.active_challenges.lock();
        if challenges.len() >= self.max_challenges {
            return Err(StorageError::Capacity);
        }
        challenges.insert(req_id.to_string(), CaptchaRequestState {
            challenge: hex::encode(challenge_bytes),
            ip: ip.to_string(),
            timestamp: timestamp.to_rfc3339(),
            difficulty,
        });
        self.active_ips.lock().insert(ip.to_string());
        Ok(())
    }

    async fn fetch_challenge(&self, req_id: &str) -> Option<CaptchaRequestState> {
        self.active_challenges.lock().get(req_id).cloned()
    }

    async fn delete_challenge(&self, req_id: &str) -> bool {
        let state = self.active_challenges.lock().remove(req_id);
        if let Some(ref s) = state {
            self.active_ips.lock().remove(&s.ip);
            return true;
        }
        false
    }

    async fn is_ip_active(&self, ip: &str) -> bool { self.active_ips.lock().contains(ip) }

    async fn increment_subnet_history(&self, subnet: &str) {
        let mut h = self.subnet_history.lock();
        *h.entry(subnet.to_string()).or_insert(0) += 1;
        Self::evict_map(&mut h);
    }

    async fn get_subnet_history(&self, subnet: &str) -> u32 {
        *self.subnet_history.lock().get(subnet).unwrap_or(&0)
    }

    async fn increment_fingerprint_history(&self, fingerprint: &str) {
        let mut h = self.fingerprint_history.lock();
        *h.entry(fingerprint.to_string()).or_insert(0) += 1;
        Self::evict_map(&mut h);
    }

    async fn get_fingerprint_history(&self, fingerprint: &str) -> u32 {
        *self.fingerprint_history.lock().get(fingerprint).unwrap_or(&0)
    }

    async fn add_global_solve(&self, timestamp: DateTime<Utc>) {
        self.global_solve_history.lock().push_back(timestamp);
    }

    async fn get_recent_global_solves_count(&self, window_seconds: i64) -> usize {
        let mut hist = self.global_solve_history.lock();
        let now = Utc::now();
        while let Some(&front) = hist.front() {
            if (now - front).num_seconds() > window_seconds { hist.pop_front(); } else { break; }
        }
        hist.len()
    }

    async fn set_max_challenges(&mut self, max: usize) {
        self.max_challenges = max;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Redis implementation (requires feature "redis")
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "redis")]
/// Lua script: atomically GET then DEL a key.
/// Prevents the TOCTOU replay-attack race that a plain pipeline has (SEC-1).
const LUA_GET_AND_DELETE: &str = r#"
local v = redis.call('GET', KEYS[1])
if v then
    redis.call('DEL', KEYS[1])
    return v
end
return false
"#;

#[cfg(feature = "redis")]
pub struct RedisStorage {
    con: redis::aio::MultiplexedConnection,
    pub max_challenges: usize,
    prefix: String,
}

#[cfg(feature = "redis")]
impl RedisStorage {
    pub async fn new(redis_url: &str, max_challenges: usize) -> Result<Self, StorageError> {
        let client = redis::Client::open(redis_url)?;
        let con = client.get_multiplexed_async_connection().await?;
        Ok(Self {
            con,
            max_challenges,
            prefix: "pow_captcha:".to_string(),
        })
    }

    pub async fn count_challenges(&self) -> usize {
        let mut con = self.con.clone();
        let now = Utc::now().timestamp();
        let key = format!("{}active_challenges_zset", self.prefix);
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&key).arg("-inf").arg(now - 300)
            .query_async(&mut con).await.unwrap_or(());
        redis::cmd("ZCARD").arg(&key).query_async(&mut con).await.unwrap_or(0)
    }

    pub async fn add_challenge(
        &self,
        req_id: &str,
        challenge_bytes: &[u8],
        ip: &str,
        difficulty: u32,
        timestamp: DateTime<Utc>,
        validity_seconds: i64,
    ) -> Result<(), StorageError> {
        let mut con = self.con.clone();
        let state = CaptchaRequestState {
            challenge: hex::encode(challenge_bytes),
            ip: ip.to_string(),
            timestamp: timestamp.to_rfc3339(),
            difficulty,
        };
        let state_json = serde_json::to_string(&state)?;

        let mut pipe = redis::pipe();
        pipe.cmd("SETEX").arg(format!("{}req:{}", self.prefix, req_id)).arg(validity_seconds).arg(&state_json);
        pipe.cmd("SETEX").arg(format!("{}ip:{}", self.prefix, ip)).arg(validity_seconds).arg("1");
        pipe.cmd("ZADD").arg(format!("{}active_challenges_zset", self.prefix)).arg(timestamp.timestamp()).arg(req_id);
        let _: () = pipe.query_async(&mut con).await?;
        Ok(())
    }

    /// Atomic get-and-delete via Lua script — eliminates replay-attack race (SEC-1).
    async fn delete_challenge(&self, req_id: &str) -> bool {
        let mut con = self.con.clone();
        let req_key = format!("{}req:{}", self.prefix, req_id);

        let raw: Option<String> = redis::Script::new(LUA_GET_AND_DELETE)
            .key(&req_key)
            .invoke_async(&mut con)
            .await
            .unwrap_or(None);

        if let Some(raw_str) = raw {
            if let Ok(state) = serde_json::from_str::<CaptchaRequestState>(&raw_str) {
                let mut pipe = redis::pipe();
                pipe.cmd("DEL").arg(format!("{}ip:{}", self.prefix, state.ip));
                pipe.cmd("ZREM").arg(format!("{}active_challenges_zset", self.prefix)).arg(req_id);
                let _: () = pipe.query_async(&mut con).await.unwrap_or(());
                return true;
            }
        }
        false
    }

    async fn is_ip_active(&self, ip: &str) -> bool {
        let mut con = self.con.clone();
        redis::cmd("EXISTS")
            .arg(format!("{}ip:{}", self.prefix, ip))
            .query_async(&mut con).await.unwrap_or(false)
    }

    pub async fn increment_subnet_history(&self, subnet: &str) {
        let mut con = self.con.clone();
        let key = format!("{}subnet:{}", self.prefix, subnet);
        let _: () = redis::cmd("INCR").arg(&key).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("EXPIRE").arg(&key).arg(86400).query_async(&mut con).await.unwrap_or(());
    }

    pub async fn get_subnet_history(&self, subnet: &str) -> u32 {
        let mut con = self.con.clone();
        redis::cmd("GET")
            .arg(format!("{}subnet:{}", self.prefix, subnet))
            .query_async(&mut con).await.unwrap_or(0)
    }

    pub async fn increment_fingerprint_history(&self, fingerprint: &str) {
        let mut con = self.con.clone();
        let key = format!("{}fingerprint:{}", self.prefix, fingerprint);
        let _: () = redis::cmd("INCR").arg(&key).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("EXPIRE").arg(&key).arg(86400).query_async(&mut con).await.unwrap_or(());
    }

    pub async fn get_fingerprint_history(&self, fingerprint: &str) -> u32 {
        let mut con = self.con.clone();
        redis::cmd("GET")
            .arg(format!("{}fingerprint:{}", self.prefix, fingerprint))
            .query_async(&mut con).await.unwrap_or(0)
    }

    pub async fn add_global_solve(&self, timestamp: DateTime<Utc>) {
        let mut con = self.con.clone();
        let key = format!("{}global_solves", self.prefix);
        let score = timestamp.timestamp();
        let member = format!("{}-{}", score, rand::random::<u32>());
        let _: () = redis::cmd("ZADD").arg(&key).arg(score).arg(&member).query_async(&mut con).await.unwrap_or(());
        let _: () = redis::cmd("ZREMRANGEBYSCORE").arg(&key).arg("-inf").arg(score - 60).query_async(&mut con).await.unwrap_or(());
    }

    pub async fn get_recent_global_solves_count(&self, window_seconds: i64) -> usize {
        let mut con = self.con.clone();
        let key = format!("{}global_solves", self.prefix);
        let now = Utc::now().timestamp();
        redis::cmd("ZCOUNT").arg(&key).arg(now - window_seconds).arg("+inf").query_async(&mut con).await.unwrap_or(0)
    }
}
