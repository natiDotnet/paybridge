//! Public verify endpoint — called by the customer's browser from the hosted
//! checkout. No API key: checkout IDs are unguessable ULIDs and the endpoint
//! is rate-limited inside the verify flow.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::docs::{VerifyResponse, VerifyFailed, VerifySucceeded};
use crate::domain::{self, VerifyResult};
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBody {
    /// Transaction reference the customer copied from their wallet app.
    pub transaction_reference: String,
}

/// Submit the customer's transaction reference for verification. The checkout
/// must be `pending`; failed verifications do not consume the checkout.
#[utoipa::path(
    post,
    path = "/api/v1/checkouts/{checkout_id}/verify",
    tag = "checkouts",
    request_body = VerifyBody,
    params(
        ("checkout_id" = String, Path, description = "Checkout id returned at creation")
    ),
    responses(
        (status = 200, description = "Verification ran: `succeeded` or `failed` with a `reason`", body = VerifyResponse),
        (status = 400, description = "Missing transactionReference", body = crate::docs::ErrorResponse),
        (status = 404, description = "Unknown checkout", body = crate::docs::ErrorResponse),
        (status = 409, description = "Checkout not payable: already succeeded, expired, or no payment method selected (error = checkout_not_pending | transaction_already_used | method_not_selected)", body = crate::docs::ErrorResponse),
        (status = 429, description = "Too many verification attempts, or retrying too fast (error = too_many_attempts | attempt_cooldown)", body = crate::docs::ErrorResponse),
        (status = 502, description = "The verification service is unavailable", body = crate::docs::ErrorResponse),
    )
)]
pub async fn verify(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    Json(body): Json<VerifyBody>,
) -> Response {
    let reference = body.transaction_reference.trim().to_string();
    if reference.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request", "message": "transactionReference is required"})),
        )
            .into_response();
    }

    match domain::verify_checkout(&state, &checkout_id, &reference).await {
        Ok(VerifyResult::Succeeded { occurred_at, .. }) => (
            StatusCode::OK,
            Json(VerifyResponse::Succeeded(VerifySucceeded {
                checkout_id,
                status: "succeeded".to_string(),
                occurred_at,
            })),
        )
            .into_response(),
        Ok(VerifyResult::Failed { reason, detail }) => (
            StatusCode::OK,
            Json(VerifyResponse::Failed(VerifyFailed {
                checkout_id,
                status: "failed".to_string(),
                reason: reason.to_string(),
                detail,
            })),
        )
            .into_response(),
        Ok(VerifyResult::AlreadyUsed) => (
            StatusCode::CONFLICT,
            Json(json!({"checkoutId": checkout_id, "error": "transaction_already_used"})),
        )
            .into_response(),
        Ok(VerifyResult::NotPending { checkout_status }) => (
            StatusCode::CONFLICT,
            Json(json!({"checkoutId": checkout_id, "error": "checkout_not_pending", "status": checkout_status})),
        )
            .into_response(),
        Ok(VerifyResult::MethodNotSelected) => (
            StatusCode::CONFLICT,
            Json(json!({"checkoutId": checkout_id, "error": "method_not_selected"})),
        )
            .into_response(),
        Ok(VerifyResult::CheckoutNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "checkout_not_found"})),
        )
            .into_response(),
        Ok(VerifyResult::TooManyAttempts) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "too_many_attempts"})),
        )
            .into_response(),
        Ok(VerifyResult::AttemptCooldown) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "attempt_cooldown"})),
        )
            .into_response(),
        Ok(VerifyResult::ServiceUnavailable(message)) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "verification_service_unavailable", "message": message})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "verify: database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error", "message": "database error"})),
            )
                .into_response()
        }
    }
}
