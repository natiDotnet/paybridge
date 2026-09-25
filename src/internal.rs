//! Internal provisioning API — service-to-service endpoints for the Rust
//! platform (the identity provider) to configure merchants here.
//!
//! Auth: `X-Internal-Service-Token` header must equal `INTERNAL_SERVICE_TOKEN`.
//! When that env var is unset the whole `/internal` surface returns 404.
//!
//! Endpoints:
//! - `POST /internal/merchants`                        upsert shadow merchant
//! - `POST /internal/merchants/{id}/methods`           add a payment method
//! - `POST /internal/merchants/{id}/webhook`           register webhook endpoint (returns secret)
//! - `POST /internal/merchants/{id}/credits`           grant credits (ledgered)

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::error::ApiError;
use crate::ids::{new_id, now_iso};
use crate::state::AppState;

const ALLOWED_PROVIDERS: [&str; 4] = ["telebirr", "cbebirr", "mpesa", "awash"];

/// Constant-time byte equality.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Service-to-service gate: `x-internal-service-token` must equal the shared
/// secret. The surface is disabled entirely when the token is unconfigured.
async fn require_service_token(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, Response> {
    let Some(expected) = state.config.service_token.clone() else {
        return Err(ApiError::not_found("not found").into_response());
    };
    let provided = req
        .headers()
        .get("x-internal-service-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
        return Err(ApiError::unauthorized().into_response());
    }
    Ok(next.run(req).await)
}

/// Sensible customer-facing steps when the platform doesn't send custom copy.
fn default_instructions(provider: &str) -> String {
    match provider {
        "cbebirr" => "Open the CBE Birr app\nSend exactly the checkout amount\nCopy the transaction reference from the confirmation\nReturn to this page and paste the reference".into(),
        "mpesa" => "Open the M-Pesa app\nSend exactly the checkout amount\nCopy the transaction reference from the confirmation\nReturn to this page and paste the reference".into(),
        "awash" => "Open the Awash app\nSend exactly the checkout amount\nCopy the transaction reference from the confirmation\nReturn to this page and paste the reference".into(),
        _ => "Open the Telebirr app and choose \"Send Money\"\nEnter the number shown above\nSend exactly the checkout amount\nCopy the transaction reference from the confirmation\nReturn to this page and paste the reference".into(),
    }
}

#[derive(Deserialize)]
pub struct UpsertMerchantRequest {
    /// The platform's merchant UUID — becomes the shadow merchant id here.
    #[serde(rename = "merchantId")]
    pub merchant_id: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// Register (or rename) a platform merchant's shadow row.
pub async fn upsert_merchant(
    State(state): State<AppState>,
    Json(req): Json<UpsertMerchantRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let merchant_id = req.merchant_id.trim();
    if merchant_id.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_merchant_id",
            "merchantId is required",
        ));
    }
    crate::auth::ensure_shadow_merchant(&state, merchant_id, req.name.as_deref()).await?;
    if let Some(name) = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        crate::db::query("UPDATE merchants SET name = ? WHERE id = ?")
            .bind(name)
            .bind(merchant_id)
            .execute(&state.pool)
            .await?;
    }
    Ok(Json(serde_json::json!({ "merchantId": merchant_id })))
}

#[derive(Deserialize)]
pub struct AddMethodRequest {
    /// `telebirr`, `cbebirr`, `mpesa`, or `awash`.
    pub provider: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// The receiving wallet/account (exact, unmasked — verification matches it).
    #[serde(rename = "accountIdentifier")]
    pub account_identifier: String,
    /// Customer-facing step-by-step instructions; defaults per provider.
    #[serde(default)]
    pub instructions: Option<String>,
}

/// Add a receiving payment method for the merchant.
pub async fn add_method(
    State(state): State<AppState>,
    Path(merchant_id): Path<String>,
    Json(req): Json<AddMethodRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let provider = req.provider.trim().to_lowercase();
    if !ALLOWED_PROVIDERS.contains(&provider.as_str()) {
        return Err(ApiError::bad_request(
            "invalid_provider",
            format!("provider must be one of: {}", ALLOWED_PROVIDERS.join(", ")),
        ));
    }
    // Ensure the merchant exists first (FK target).
    crate::auth::ensure_shadow_merchant(&state, &merchant_id, None).await?;

    let display_name = req.display_name.trim().to_string();
    let account = req.account_identifier.trim().to_string();
    if display_name.is_empty() || account.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_method",
            "displayName and accountIdentifier are required",
        ));
    }
    let instructions = req
        .instructions
        .clone()
        .filter(|i| !i.trim().is_empty())
        .unwrap_or_else(|| default_instructions(&provider));

    crate::db::query(
        "INSERT INTO merchant_payment_methods \
         (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("mpm"))
    .bind(&merchant_id)
    .bind(&provider)
    .bind(display_name)
    .bind(account)
    .bind(instructions)
    .bind(now_iso())
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "provider": provider })),
    ))
}

#[derive(Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
}

/// Register the merchant's webhook endpoint. For platform merchants this is
/// the Rust platform's receiver (`POST /api/payments/webhook/paybridge`); the
/// returned secret is what the platform stores to verify `X-PayBridge-Signature`.
pub async fn register_webhook(
    State(state): State<AppState>,
    Path(merchant_id): Path<String>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let url = req.url.trim();
    let parsed = url::Url::parse(url)
        .map_err(|_| ApiError::bad_request("invalid_url", "url must be an absolute URL"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ApiError::bad_request(
            "invalid_webhook_url",
            "webhook url must be http(s)",
        ));
    }
    crate::auth::ensure_shadow_merchant(&state, &merchant_id, None).await?;

    // 160 bits of OS randomness via two ULIDs, same recipe as the portal.
    let secret = format!("whsec_{}{}", ulid::Ulid::new(), ulid::Ulid::new());
    // Replace any previous active endpoint: the dispatcher delivers to one
    // active endpoint per merchant (LIMIT 1).
    crate::db::query(
        "UPDATE webhook_endpoints SET status = 'disabled' \
         WHERE merchant_id = ? AND status = 'active'",
    )
    .bind(&merchant_id)
    .execute(&state.pool)
    .await?;
    crate::db::query(
        "INSERT INTO webhook_endpoints (id, merchant_id, url, secret, status, created_at) \
         VALUES (?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("whe"))
    .bind(&merchant_id)
    .bind(url)
    .bind(&secret)
    .bind(now_iso())
    .execute(&state.pool)
    .await?;

    Ok(Json(serde_json::json!({ "secret": secret })))
}

#[derive(Deserialize)]
pub struct GrantCreditsRequest {
    /// Positive number of credits to add.
    pub credits: i64,
}

/// Grant verification credits (ledgered as an admin_grant).
pub async fn grant_credits(
    State(state): State<AppState>,
    Path(merchant_id): Path<String>,
    Json(req): Json<GrantCreditsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.credits <= 0 {
        return Err(ApiError::bad_request("invalid_credits", "credits must be positive"));
    }
    // Ensure the merchant exists so the ledger FK is satisfiable.
    crate::auth::ensure_shadow_merchant(&state, &merchant_id, None).await?;
    crate::db::query("UPDATE merchants SET credit_balance = credit_balance + ? WHERE id = ?")
        .bind(req.credits)
        .bind(&merchant_id)
        .execute(&state.pool)
        .await?;
    crate::db::query(
        "INSERT INTO credit_ledger (id, merchant_id, delta, reason, checkout_id, created_at) \
         VALUES (?, ?, ?, 'admin_grant', NULL, ?)",
    )
    .bind(new_id("crl"))
    .bind(&merchant_id)
    .bind(req.credits)
    .bind(now_iso())
    .execute(&state.pool)
    .await?;

    let (balance,) = crate::db::query_as::<(i64,)>(
        "SELECT credit_balance FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(
        serde_json::json!({ "merchantId": merchant_id, "creditBalance": balance }),
    ))
}

/// Router for the /internal surface; mounted at the root by app.rs. State is
/// provided by the parent router's `with_state`.
pub fn router(state: AppState) -> axum::Router<AppState> {
    Router::new()
        .route("/merchants", post(upsert_merchant))
        .route("/merchants/{merchant_id}/methods", post(add_method))
        .route("/merchants/{merchant_id}/webhook", post(register_webhook))
        .route("/merchants/{merchant_id}/credits", post(grant_credits))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
}
