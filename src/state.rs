use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::db::Pool;

use crate::config::Config;
use crate::verify::Verifier;

/// Cache entry for a resolved `hp_…` API key.
#[derive(Clone)]
struct CachedKey {
    pub merchant_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Instant,
}

/// Thread-safe cache of `hp_…` key resolutions, keyed by prefix (first 12
/// chars after "hp_"). Entries expire after `key_cache_ttl`.
pub struct AuthCache(Mutex<HashMap<String, CachedKey>>);

impl AuthCache {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    pub fn get(&self, prefix: &str, _ttl: Duration) -> Option<(String, Vec<String>)> {
        let guard = self.0.lock().ok()?;
        guard.get(prefix).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some((entry.merchant_id.clone(), entry.scopes.clone()))
            } else {
                None
            }
        })
    }

    pub fn set(&self, prefix: String, merchant_id: String, scopes: Vec<String>, ttl: Duration) {
        if let Ok(mut guard) = self.0.lock() {
            guard.insert(prefix, CachedKey { merchant_id, scopes, expires_at: Instant::now() + ttl });
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub config: Arc<Config>,
    pub verifier: Arc<Verifier>,
    /// Shared HTTP client for webhook delivery and the verification service.
    pub http: reqwest::Client,
    /// Cached `hp_…` key resolutions.
    pub auth_cache: Arc<AuthCache>,
}
