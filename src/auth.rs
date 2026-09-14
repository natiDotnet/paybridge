//! Merchant authentication: `Authorization: Bearer pb_sk_...`.
//! Keys are stored as SHA-256 hashes; lookup happens by a stored prefix so a
//! full-table scan of hashes is unnecessary.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::db;
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

        let prefix = &token[..12];
        let hash = sha256_hex(token);
        let row = db::query_as::<(String, String, i64)>(
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

        row.map(|(merchant_id, merchant_name, credit_balance)| Self {
            merchant_id,
            merchant_name,
            credit_balance,
        })
        .ok_or_else(ApiError::unauthorized)
    }
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
