//! Merchant-facing JSON API: create + inspect checkouts.
//! Auth: `Authorization: Bearer pb_sk_…` (see auth.rs).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::MerchantAuth;
use crate::error::ApiError;
use crate::ids::{new_id, now_iso};
use crate::money::{format_minor, number_to_minor};
use crate::state::AppState;

/// Merchant's own order reference; replays with the same `Idempotency-Key`
/// header return the original checkout instead of a new one.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateCheckoutRequest {
    /// Merchant-side order id, echoed back in webhooks.
    pub reference: String,
    /// Amount to collect, e.g. 500 or 500.50 (at most 2 decimal places).
    #[schema(value_type = f64)]
    pub amount: serde_json::Number,
    /// ISO currency code; only `ETB` is supported in v1.
    pub currency: String,
    #[serde(default)]
    pub items: Option<Vec<CreateItem>>,
    #[serde(default)]
    pub customer: Option<CreateCustomer>,
    /// Browser redirect after a successful payment; the hosted page appends
    /// `checkoutId`, `reference` and `status=succeeded` query parameters.
    #[serde(default)]
    pub return_url: Option<String>,
    /// Checkout lifetime in seconds; default 24 h, minimum 60, maximum 7 days.
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateItem {
    pub name: String,
    pub quantity: i64,
    #[schema(value_type = f64)]
    pub unit_price: serde_json::Number,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateCustomer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutDto {
    pub checkout_id: String,
    pub payment_url: String,
    pub reference: String,
    /// Decimal string, e.g. "500.00" — no floats across the wire.
    pub amount: String,
    pub amount_minor: i64,
    pub currency: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ItemDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<CustomerDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<MethodDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_reference: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<String>,
    pub attempts: i64,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ItemDto {
    pub name: String,
    pub quantity: i64,
    pub unit_price: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CustomerDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MethodDto {
    pub provider: String,
    pub display_name: String,
}

struct ParsedCheckout {
    amount_minor: i64,
    items: Option<Vec<(String, i64, i64)>>,
    customer: Option<(Option<String>, Option<String>)>,
    return_url: Option<String>,
    expires_at: String,
}

fn parse_request(req: &CreateCheckoutRequest, config: &crate::config::Config) -> Result<ParsedCheckout, ApiError> {
    if req.reference.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_reference", "reference is required"));
    }
    let amount_minor = number_to_minor(&req.amount)
        .map_err(|m| ApiError::bad_request("invalid_amount", m))?;
    if amount_minor <= 0 {
        return Err(ApiError::bad_request("invalid_amount", "amount must be greater than zero"));
    }
    if !req.currency.eq_ignore_ascii_case("ETB") {
        return Err(ApiError::bad_request("invalid_currency", "only ETB is supported in v1"));
    }

    let items = match &req.items {
        None => None,
        Some(items) => {
            if items.is_empty() {
                return Err(ApiError::bad_request("invalid_items", "items must not be empty"));
            }
            let mut parsed = Vec::with_capacity(items.len());
            let mut sum: i64 = 0;
            for item in items {
                if item.quantity <= 0 {
                    return Err(ApiError::bad_request("invalid_items", "item quantity must be positive"));
                }
                let unit = number_to_minor(&item.unit_price)
                    .map_err(|m| ApiError::bad_request("invalid_items", m))?;
                let line = item
                    .quantity
                    .checked_mul(unit)
                    .ok_or_else(|| ApiError::bad_request("invalid_items", "item amount overflow"))?;
                sum = sum
                    .checked_add(line)
                    .ok_or_else(|| ApiError::bad_request("invalid_items", "item amount overflow"))?;
                parsed.push((item.name.trim().to_string(), item.quantity, unit));
            }
            if sum != amount_minor {
                return Err(ApiError::bad_request(
                    "amount_items_mismatch",
                    format!("amount {} does not match items total {}", format_minor(amount_minor), format_minor(sum)),
                ));
            }
            Some(parsed)
        }
    };

    let return_url = match &req.return_url {
        None => None,
        Some(url) if url.trim().is_empty() => None,
        Some(url) => {
            let parsed = url::Url::parse(url.trim())
                .map_err(|_| ApiError::bad_request("invalid_return_url", "returnUrl must be an absolute URL"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(ApiError::bad_request("invalid_return_url", "returnUrl must be http(s)"));
            }
            Some(url.trim().to_string())
        }
    };

    let ttl_secs = match req.expires_in_seconds {
        None => config.checkout_ttl_default.as_secs() as i64,
        Some(secs) if secs < 60 => {
            return Err(ApiError::bad_request("invalid_expiry", "expiresInSeconds must be at least 60"))
        }
        Some(secs) => secs.min(config.checkout_ttl_max.as_secs() as i64),
    };
    let expires_at = crate::ids::to_iso(chrono::Utc::now() + chrono::Duration::seconds(ttl_secs));

    let customer = req.customer.as_ref().map(|c| {
        (
            c.name.as_ref().map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
            c.email.as_ref().map(|e| e.trim().to_string()).filter(|e| !e.is_empty()),
        )
    });

    Ok(ParsedCheckout { amount_minor, items, customer, return_url, expires_at })
}

fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
}

/// Create a checkout. Redirect the customer to the returned `paymentUrl` to
/// collect the payment. Replays with the same `Idempotency-Key` header return
/// the original checkout.
#[utoipa::path(
    post,
    path = "/api/v1/checkouts",
    tag = "checkouts",
    request_body = CreateCheckoutRequest,
    responses(
        (status = 201, description = "Checkout created (also returned for Idempotency-Key replays, with the current status)", body = CheckoutDto),
        (status = 400, description = "Validation failed (invalid_amount, invalid_currency, amount_items_mismatch, invalid_return_url, invalid_expiry, ...)", body = crate::docs::ErrorResponse),
        (status = 401, description = "Invalid or missing API key", body = crate::docs::ErrorResponse),
    )
)]
pub async fn create_checkout(
    State(state): State<AppState>,
    auth: MerchantAuth,
    headers: HeaderMap,
    Json(req): Json<CreateCheckoutRequest>,
) -> Result<Response, ApiError> {
    let parsed = parse_request(&req, &state.config)?;

    // Idempotent replay: same merchant + Idempotency-Key -> same checkout.
    if let Some(key) = idempotency_key(&headers) {
        if let Some((existing,)) = sqlx::query_as::<_, (String,)>(
            "SELECT checkout_id FROM idempotency_keys WHERE merchant_id = ? AND key = ?",
        )
        .bind(&auth.merchant_id)
        .bind(&key)
        .fetch_optional(&state.pool)
        .await?
        {
            let dto = load_checkout_dto(&state, &existing)
                .await?
                .ok_or_else(|| ApiError::internal("idempotent checkout missing"))?;
            return Ok((StatusCode::CREATED, Json(dto)).into_response());
        }
    }

    let checkout_id = new_id("chk");
    let mut db = state.pool.begin().await?;

    // Insert the checkout first: the idempotency row has a FK to it.
    let (customer_name, customer_email) = parsed
        .customer
        .clone()
        .map(|(n, e)| (n, e))
        .unwrap_or((None, None));

    sqlx::query(
        "INSERT INTO checkouts \
         (id, merchant_id, reference, amount_minor, currency, status, customer_name, customer_email, return_url, selected_method_id, expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 'created', ?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(&checkout_id)
    .bind(&auth.merchant_id)
    .bind(req.reference.trim())
    .bind(parsed.amount_minor)
    .bind(req.currency.to_uppercase())
    .bind(&customer_name)
    .bind(&customer_email)
    .bind(&parsed.return_url)
    .bind(&parsed.expires_at)
    .bind(now_iso())
    .bind(now_iso())
    .execute(&mut *db)
    .await?;

    if let Some(items) = &parsed.items {
        for (name, quantity, unit_price) in items {
            sqlx::query(
                "INSERT INTO checkout_items (id, checkout_id, name, quantity, unit_price_minor) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(new_id("itm"))
            .bind(&checkout_id)
            .bind(name)
            .bind(quantity)
            .bind(unit_price)
            .execute(&mut *db)
            .await?;
        }
    }

    // Claim the idempotency key now that the checkout exists. A concurrent
    // request that won the race causes our insert to be ignored: we roll back
    // (removing this checkout) and return the winner's.
    if let Some(key) = idempotency_key(&headers) {
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO idempotency_keys (merchant_id, key, checkout_id, created_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&auth.merchant_id)
        .bind(&key)
        .bind(&checkout_id)
        .bind(now_iso())
        .execute(&mut *db)
        .await?;
        if inserted.rows_affected() == 0 {
            db.rollback().await?;
            let (existing,): (String,) = sqlx::query_as(
                "SELECT checkout_id FROM idempotency_keys WHERE merchant_id = ? AND key = ?",
            )
            .bind(&auth.merchant_id)
            .bind(&key)
            .fetch_one(&state.pool)
            .await?;
            let dto = load_checkout_dto(&state, &existing)
                .await?
                .ok_or_else(|| ApiError::internal("idempotent checkout missing"))?;
            return Ok((StatusCode::CREATED, Json(dto)).into_response());
        }
    }

    db.commit().await?;

    tracing::info!(checkout_id = %checkout_id, merchant_id = %auth.merchant_id, "checkout created");
    let dto = load_checkout_dto(&state, &checkout_id)
        .await?
        .ok_or_else(|| ApiError::internal("checkout missing after insert"))?;
    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// Inspect a checkout: current status, selected payment method, and the
/// consumed `transactionReference` once it is paid.
#[utoipa::path(
    get,
    path = "/api/v1/checkouts/{checkout_id}",
    tag = "checkouts",
    params(
        ("checkout_id" = String, Path, description = "Checkout id returned at creation")
    ),
    responses(
        (status = 200, description = "Current checkout state", body = CheckoutDto),
        (status = 401, description = "Invalid or missing API key", body = crate::docs::ErrorResponse),
        (status = 404, description = "Unknown checkout or owned by a different merchant", body = crate::docs::ErrorResponse),
    )
)]
pub async fn get_checkout(
    State(state): State<AppState>,
    auth: MerchantAuth,
    Path(checkout_id): Path<String>,
) -> Result<Json<CheckoutDto>, ApiError> {
    // Ownership check before loading: merchants must only see their own
    // checkouts (mismatches return the same 404 as unknown ids).
    let owner = sqlx::query_as::<_, (String,)>(
        "SELECT merchant_id FROM checkouts WHERE id = ?",
    )
    .bind(&checkout_id)
    .fetch_optional(&state.pool)
    .await?;
    if owner.as_ref().map(|(m,)| m.as_str()) != Some(auth.merchant_id.as_str()) {
        return Err(ApiError::not_found("checkout not found"));
    }

    let dto = load_checkout_dto(&state, &checkout_id)
        .await?
        .ok_or_else(|| ApiError::not_found("checkout not found"))?;
    Ok(Json(dto))
}

pub async fn load_checkout_dto(
    state: &AppState,
    checkout_id: &str,
) -> Result<Option<CheckoutDto>, sqlx::Error> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, merchant_id, reference, amount_minor, currency, status, customer_name, customer_email, return_url, selected_method_id, expires_at, created_at, paid_at \
         FROM checkouts WHERE id = ?",
    )
    .bind(checkout_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((
        id,
        _merchant_id,
        reference,
        amount_minor,
        currency,
        status,
        customer_name,
        customer_email,
        return_url,
        selected_method_id,
        expires_at,
        created_at,
        paid_at,
    )) = row
    else {
        return Ok(None);
    };

    let items = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT name, quantity, unit_price_minor FROM checkout_items WHERE checkout_id = ? ORDER BY id",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;
    let items_dto = if items.is_empty() {
        None
    } else {
        Some(
            items
                .into_iter()
                .map(|(name, quantity, unit_price)| ItemDto {
                    name,
                    quantity,
                    unit_price: format_minor(unit_price),
                })
                .collect(),
        )
    };

    let payment_method = match &selected_method_id {
        Some(method_id) => sqlx::query_as::<_, (String, String)>(
            "SELECT provider, display_name FROM merchant_payment_methods WHERE id = ?",
        )
        .bind(method_id)
        .fetch_optional(&state.pool)
        .await?
        .map(|(provider, display_name)| MethodDto { provider, display_name }),
        None => None,
    };

    let transaction_reference = sqlx::query_as::<_, (String,)>(
        "SELECT t.transaction_reference FROM transactions t \
         JOIN payments p ON p.id = t.payment_id \
         WHERE p.checkout_id = ? AND p.status = 'succeeded' \
         ORDER BY t.created_at DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .map(|(r,)| r);

    let (attempts,) = sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM payment_attempts WHERE checkout_id = ? AND outcome != 'verification_service_error'",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Some(CheckoutDto {
        checkout_id: id.clone(),
        payment_url: format!("{}/c/{}", state.config.base_url, id),
        reference,
        amount: format_minor(amount_minor),
        amount_minor,
        currency,
        status,
        items: items_dto,
        customer: if customer_name.is_some() || customer_email.is_some() {
            Some(CustomerDto {
                name: customer_name,
                email: customer_email,
            })
        } else {
            None
        },
        return_url,
        payment_method,
        transaction_reference,
        expires_at,
        created_at,
        paid_at,
        attempts,
    }))
}
