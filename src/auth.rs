//! Merchant authentication.
//!
//! Two credential families are accepted in `Authorization: Bearer <token>`:
//!
//! - `hp_…` — keys issued by the Rust platform (the identity provider).
//!   Resolved via the platform's `POST /internal/keys/verify` introspection
//!   endpoint (service-token authenticated, cached by prefix for
//!   `key_cache_ttl`). The merchant row in the local DB is a *shadow*
//!   record keyed by the platform's merchant UUID; it is created lazily on
//!   first use and refined by the /internal provisioning API.
//!
//! - `pb_sk_…` — legacy locally issued keys (SHA-256 hashed, stored in
//!   `merchant_api_keys`). Kept for standalone operation and the dev seed.
//!
//! Both paths store only hashes; lookup happens by a stored prefix so a
//! full-table scan of hashes is unnecessary.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::AppState;

pub struct MerchantAuth {
    pub merchant_id: String,
    #[allow(dead_code)]
    pub merchant_name: String,
    /// Prepaid verification credits; checkout creation requires >= 1.
    pub credit_balance: i64,
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

impl FromRequestParts<AppState> for MerchantAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = header.strip_prefix("Bearer ").map(str::trim).unwrap_or("");
        if token.len() < 12 {
            return Err(ApiError::unauthorized());
        }

        if token.starts_with("hp_") {
            return authenticate_platform_key(state, token).await;
        }
        authenticate_local_key(state, token).await
    }
}

/// Legacy path: locally issued `pb_sk_…` key (SHA-256 hash lookup).
async fn authenticate_local_key(state: &AppState, token: &str) -> Result<MerchantAuth, ApiError> {
    let prefix = &token[..12];
    let hash = sha256_hex(token);
    let row = crate::db::query_as::<(String, String, i64)>(
        "SELECT k.merchant_id, m.name, m.credit_balance \
         FROM merchant_api_keys k \
         JOIN merchants m ON m.id = k.merchant_id \
         WHERE k.prefix = ? AND k.key_hash = ? \
           AND k.revoked_at IS NULL AND m.status = 'active' \
           AND m.onboarding_status = 'approved'",
    )
    .bind(prefix)
    .bind(hash)
    .fetch_optional(&state.pool)
    .await?;

    row.map(|(merchant_id, merchant_name, credit_balance)| MerchantAuth {
        merchant_id,
        merchant_name,
        credit_balance,
    })
    .ok_or_else(ApiError::unauthorized)
}

/// Introspection response from the Rust platform (`POST /internal/keys/verify`).
#[derive(Deserialize)]
struct IntrospectionResponse {
    valid: bool,
    #[serde(default)]
    merchant_id: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

/// Platform path: resolve an `hp_…` key against the Rust platform, then make
/// sure a shadow merchant row exists locally (created lazily on first use).
async fn authenticate_platform_key(
    state: &AppState,
    token: &str,
) -> Result<MerchantAuth, ApiError> {
    let prefix = token
        .strip_prefix("hp_")
        .and_then(|rest| rest.get(..12))
        .ok_or_else(ApiError::unauthorized)?;

    if let Some((merchant_id, _)) = state.auth_cache.get(prefix, state.config.key_cache_ttl) {
        return load_shadow_merchant(state, &merchant_id).await;
    }

    let Some(internal_url) = state.config.rust_internal_url.as_deref() else {
        tracing::warn!("hp_ key rejected: RUST_INTERNAL_URL not configured");
        return Err(ApiError::unauthorized());
    };
    let Some(service_token) = state.config.service_token.clone() else {
        tracing::warn!("hp_ key rejected: INTERNAL_SERVICE_TOKEN not configured");
        return Err(ApiError::unauthorized());
    };

    let response = state
        .http
        .post(format!("{internal_url}/internal/keys/verify"))
        .header("x-internal-service-token", service_token)
        .json(&serde_json::json!({ "key": token }))
        .send()
        .await;

    let response = match response {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "key introspection rejected by platform");
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "identity_service_error",
                "the platform identity service rejected the introspection request",
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "key introspection call failed");
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "identity_service_unavailable",
                "could not reach the platform identity service",
            ));
        }
    };

    let introspection: IntrospectionResponse = response
        .json()
        .await
        .map_err(|_| ApiError::internal("unparseable introspection response"))?;

    if !introspection.valid {
        return Err(ApiError::unauthorized());
    }
    let Some(merchant_id) = introspection.merchant_id else {
        return Err(ApiError::internal("introspection missing merchant_id"));
    };

    // Scope gate: the key must be a payment-creating key. Empty scopes are
    // treated as unscoped (allowed).
    if let Some(scopes) = &introspection.scopes {
        if !scopes.is_empty()
            && !scopes.iter().any(|s| s == "payment.create" || s == "checkout.create")
        {
            return Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "insufficient_scope",
                "this API key may not create checkouts",
            ));
        }
    }

    state.auth_cache.set(
        prefix.to_string(),
        merchant_id.clone(),
        introspection.scopes.unwrap_or_default(),
        state.config.key_cache_ttl,
    );

    load_shadow_merchant(state, &merchant_id).await
}

/// Load (creating if needed) the local shadow merchant for a platform
/// merchant id. Provisioning refines name/wallets/webhook endpoint later.
async fn load_shadow_merchant(state: &AppState, merchant_id: &str) -> Result<MerchantAuth, ApiError> {
    ensure_shadow_merchant(state, merchant_id, None).await?;
    let row = crate::db::query_as::<(String, i64)>(
        "SELECT name, credit_balance FROM merchants \
         WHERE id = ? AND status = 'active' AND onboarding_status = 'approved'",
    )
    .bind(merchant_id)
    .fetch_optional(&state.pool)
    .await?;

    row.map(|(merchant_name, credit_balance)| MerchantAuth {
        merchant_id: merchant_id.to_string(),
        merchant_name,
        credit_balance,
    })
    .ok_or_else(ApiError::unauthorized)
}

/// Idempotently create the shadow merchant row. `name` overrides the generic
/// default (used by the /internal provisioning API).
pub async fn ensure_shadow_merchant(
    state: &AppState,
    merchant_id: &str,
    name: Option<&str>,
) -> Result<(), crate::error::ApiError> {
    let name = name.unwrap_or("Platform merchant");
    crate::db::query(
        "INSERT INTO merchants (id, name, status, onboarding_status, credit_balance, created_at) \
         VALUES (?, ?, 'active', 'approved', ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(merchant_id)
    .bind(name)
    .bind(state.config.initial_credits)
    .bind(crate::ids::now_iso())
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// HMAC-SHA256 as hex — used for webhook signatures (constant-time compare
/// happens on the merchant side; here we only produce signatures).
#[allow(dead_code)]
pub fn hmac_sha256_hex(secret: &str, data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}
