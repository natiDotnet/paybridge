//! Minimal webhook receiver for local testing: prints every delivery and
//! verifies the PayBridge HMAC signature. Run with:
//!   cargo run --example webhook_echo
//! It listens on :4001 (the URL configured in the dev seed).

use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &str = "whsec_seed_acme_0123456789abcdef0123456789abcdef";

#[tokio::main]
async fn main() {
    let app = axum::Router::new().route(
        "/webhooks",
        axum::routing::post(
            |headers: axum::http::HeaderMap, body: String| async move {
                let signature = headers
                    .get("x-paybridge-signature")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
                mac.update(body.as_bytes());
                let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
                let ok = signature == expected;

                println!("--- webhook received ------------------");
                println!("event-id: {:?}", headers.get("x-paybridge-event-id"));
                println!("signature_valid: {ok}");
                println!("body: {body}");
                if !ok {
                    println!("expected: {expected}");
                }

                // Simulate a merchant that sometimes fails (force retries by
                // sending "fail" as the response).
                if body.contains("\"fail-test\"") {
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
                } else {
                    (axum::http::StatusCode::OK, "ok")
                }
            },
        ),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4001").await.unwrap();
    println!("webhook echo receiver listening on http://0.0.0.0:4001/webhooks");
    axum::serve(listener, app).await.unwrap();
}
