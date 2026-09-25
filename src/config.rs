//! Environment configuration. Every value has a working dev default.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierKind {
    Mock,
    Http,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    /// Public origin used to build `paymentUrl` for merchants.
    pub base_url: String,
    pub verifier: VerifierKind,
    pub verify_service_url: Option<String>,
    pub verify_service_api_key: Option<String>,
    pub checkout_ttl_default: Duration,
    pub checkout_ttl_max: Duration,
    pub verify_max_attempts: i64,
    pub verify_cooldown: Duration,
    /// Delay before retry attempt N+1 (index 0 = delay before attempt 2).
    pub webhook_schedule: Vec<Duration>,
    pub worker_poll_interval: Duration,
    /// Directory with static assets (payment-app walkthrough slides etc.).
    pub static_dir: std::path::PathBuf,
    /// Password for the /admin portal (single shared admin; roles come later).
    pub admin_password: String,
    /// Email of the bootstrapped superadmin user (see admin::ensure_bootstrap_admin).
    pub admin_email: String,
    /// Rust platform base URL for `hp_…` API-key introspection. When unset,
    /// only local `pb_sk_…` keys work (legacy/standalone mode).
    pub rust_internal_url: Option<String>,
    /// Shared service-to-service secret (matches the platform's
    /// INTERNAL_SERVICE_TOKEN). Gates both key introspection and the
    /// /internal provisioning endpoints. Unset = both disabled.
    pub service_token: Option<String>,
    /// Credits granted to a lazily-created shadow merchant on first use.
    pub initial_credits: i64,
    /// How long a resolved `hp_…` key identity stays cached. Bounds the
    /// revocation lag when a key is revoked on the platform.
    pub key_cache_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Self {
        let get = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());

        let verifier = match get("VERIFIER").as_deref() {
            Some("http") => VerifierKind::Http,
            _ => VerifierKind::Mock,
        };

        Self {
            bind: get("PAYBRIDGE_BIND").unwrap_or_else(|| "0.0.0.0:4000".into()),
            database_url: get("DATABASE_URL")
                .unwrap_or_else(|| "sqlite://paybridge.db?mode=rwc".into()),
            base_url: get("PAYBRIDGE_BASE_URL")
                .unwrap_or_else(|| "http://localhost:4000".into())
                .trim_end_matches('/')
                .to_string(),
            verifier,
            verify_service_url: get("VERIFY_SERVICE_URL"),
            verify_service_api_key: get("VERIFY_SERVICE_API_KEY"),
            checkout_ttl_default: duration_env("CHECKOUT_TTL_DEFAULT", Duration::from_secs(86_400)),
            checkout_ttl_max: duration_env("CHECKOUT_TTL_MAX", Duration::from_secs(7 * 86_400)),
            verify_max_attempts: get("VERIFY_MAX_ATTEMPTS_PER_CHECKOUT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            verify_cooldown: duration_env("VERIFY_ATTEMPT_COOLDOWN", Duration::from_secs(5)),
            webhook_schedule: schedule_env(
                "WEBHOOK_RETRY_SCHEDULE",
                "0s,30s,2m,10m,45m,2h,6h,24h",
            ),
            worker_poll_interval: duration_env("WORKER_POLL_INTERVAL", Duration::from_secs(5)),
            static_dir: std::path::PathBuf::from(
                get("PAYBRIDGE_STATIC_DIR").unwrap_or_else(|| "static".into()),
            ),
            admin_password: get("PAYBRIDGE_ADMIN_PASSWORD").unwrap_or_else(|| {
                tracing::warn!("PAYBRIDGE_ADMIN_PASSWORD not set; using the dev default — set it before exposing /admin");
                "paybridge-admin".into()
            }),
            admin_email: get("PAYBRIDGE_ADMIN_EMAIL")
                .unwrap_or_else(|| "admin@paybridge.local".into()),
            rust_internal_url: get("RUST_INTERNAL_URL").map(|u| u.trim_end_matches('/').to_string()),
            service_token: get("INTERNAL_SERVICE_TOKEN"),
            initial_credits: get("PAYBRIDGE_INITIAL_CREDITS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            key_cache_ttl: duration_env("KEY_CACHE_TTL", Duration::from_secs(300)),
        }
    }
}

fn duration_env(key: &str, default: Duration) -> Duration {
    std::env::var(key)
        .ok()
        .and_then(|v| humantime::parse_duration(&v).ok())
        .unwrap_or(default)
}

fn schedule_env(key: &str, default: &str) -> Vec<Duration> {
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.split(',')
        .filter_map(|part| humantime::parse_duration(part.trim()).ok())
        .collect()
}
