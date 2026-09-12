//! Router assembly, shared by the binary and the integration tests.

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

/// Security headers for customer-facing hosted pages: no framing, no caching,
/// and no referrer leakage to merchants.
async fn hosted_security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    response
}

pub fn build_app(state: AppState) -> Router {
    let hosted = Router::new()
        .route("/{checkout_id}", get(crate::hosted::checkout_page))
        .route("/{checkout_id}/method", post(crate::hosted::select_method))
        .route("/{checkout_id}/verify", post(crate::hosted::verify_form))
        .layer(middleware::from_fn(hosted_security_headers))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/", get(crate::hosted::index))
        .route("/api/v1/checkouts", post(crate::api::create_checkout))
        .route(
            "/api/v1/checkouts/{checkout_id}",
            get(crate::api::get_checkout),
        )
        .route(
            "/api/v1/checkouts/{checkout_id}/verify",
            post(crate::public_verify::verify),
        )
        .nest("/c", hosted)
        .route("/docs", get(crate::docs::scalar_docs))
        .route("/api-docs/openapi.json", get(crate::docs::openapi_json))
        .with_state(state)
}
