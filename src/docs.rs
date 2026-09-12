//! OpenAPI generation (utoipa) and the Scalar UI page served at `/docs`.

use axum::response::Html;
use axum::Json;
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

use crate::api::{CheckoutDto, CreateCheckoutRequest, CustomerDto, ItemDto, MethodDto};
use crate::public_verify::VerifyBody;

/// Documented shape of the verify endpoint's JSON response: `succeeded`
/// (with `occurredAt`) or `failed` (with `reason` and optional `detail`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum VerifyResponse {
    Succeeded(VerifySucceeded),
    Failed(VerifyFailed),
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifySucceeded {
    pub checkout_id: String,
    pub status: String,
    /// ISO-8601 timestamp of the original wallet transaction.
    pub occurred_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFailed {
    pub checkout_id: String,
    pub status: String,
    /// One of: transaction_not_found, transaction_not_successful,
    /// transaction_too_old, amount_mismatch, currency_mismatch,
    /// recipient_mismatch.
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Documented shape of error responses: `{ "error": code, "message": ... }`.
/// Some non-2xx responses (409/429) carry additional context fields such as
/// `checkoutId` or `status` alongside `error`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// Referenced only by the #[openapi(paths(...))] macro; there is no runtime caller.
#[allow(dead_code)]
#[utoipa::path(
    get,
    path = "/health",
    tag = "meta",
    responses((status = 200, description = "Service is healthy; body is `ok`"))
)]
pub fn health() {}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "PayBridge Checkout API",
        version = "0.1.0",
        description = "Hosted checkout + transaction-reference payment verification for Ethiopian \
                       wallet payments (Telebirr first).\n\n\
                       **Merchant flow:** create a checkout with `POST /api/v1/checkouts`, redirect the \
                       customer to the returned `paymentUrl` (a hosted page where they pay your \
                       configured wallet and enter the transaction reference), then receive \
                       `checkout.payment_succeeded` on your webhook endpoint. Confirm final status \
                       any time with `GET /api/v1/checkouts/{checkoutId}`.\n\n\
                       `POST /api/v1/checkouts/{checkoutId}/verify` is the public endpoint the hosted \
                       page itself calls; it is rate-limited and safe to use from your own front end.\
                       \n\nThe hosted pages under `/c/{checkoutId}` are browser flows and are \
                       intentionally not part of this API document."
    ),
    paths(
        health,
        crate::api::create_checkout,
        crate::api::get_checkout,
        crate::public_verify::verify,
    ),
    components(schemas(
        CreateCheckoutRequest,
        CheckoutDto,
        ItemDto,
        CustomerDto,
        MethodDto,
        VerifyBody,
        VerifyResponse,
        VerifySucceeded,
        VerifyFailed,
        ErrorResponse,
    ))
)]
pub struct ApiDoc;

pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Minimal Scalar API-reference page bound to the generated OpenAPI document.
/// Scalar is loaded from the public CDN, so docs need no build step.
const SCALAR_HTML: &str = r#"<!doctype html>
<html>
  <head>
    <title>PayBridge API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="/api-docs/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"#;

pub async fn scalar_docs() -> Html<&'static str> {
    Html(SCALAR_HTML)
}
