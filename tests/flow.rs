//! End-to-end flow test against the real router + in-process mock verifier:
//! create → idempotent replay → method selection → verification chain →
//! terminal state → transaction reuse → outbox webhook delivery (signature +
//! retry). Hosted-page routing/CSRF is covered by the manual smoke test
//! documented in the README.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{routing, Router};
use paybridge::auth::sha256_hex;
use paybridge::config::{Config, VerifierKind};
use paybridge::state::AppState;
use paybridge::{app::build_app, webhooks};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const API_KEY: &str = "pb_sk_test_integration_key";
const WEBHOOK_SECRET: &str = "whsec_test_0123456789abcdef0123456789abcd";
const MERCHANT: &str = "mch_test";
const METHOD: &str = "mpm_test";

type Headers = Vec<(String, String)>;

#[tokio::test(flavor = "multi_thread")]
async fn full_checkout_flow() {
    // --- webhook receiver on an ephemeral port ------------------------------
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String, String)>(16);
    let fail_mode = Arc::new(AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint_addr = listener.local_addr().unwrap();
    let receiver = Router::new()
        .route("/webhooks", routing::post(handle_webhook).with_state(ReceiverState { tx, fail: fail_mode.clone() }));
    tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });

    // --- database + seed ------------------------------------------------------
    let tmp = tempfile::tempdir().unwrap();
    let db_url = format!(
        "sqlite://{}/paybridge.db?mode=rwc",
        tmp.path().display().to_string().replace('\\', "/")
    );
    let pool = SqlitePool::connect(&db_url).await.unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    seed(&pool, &format!("http://{endpoint_addr}/webhooks")).await;

    // --- app state + router ---------------------------------------------------
    let config = Arc::new(Config {
        bind: "127.0.0.1:0".into(),
        database_url: db_url.clone(),
        base_url: "http://paybridge.test".into(),
        verifier: VerifierKind::Mock,
        verify_service_url: None,
        verify_service_api_key: None,
        checkout_ttl_default: Duration::from_secs(3600),
        checkout_ttl_max: Duration::from_secs(7 * 86_400),
        verify_max_attempts: 10,
        verify_cooldown: Duration::ZERO,
        webhook_schedule: vec![Duration::ZERO, Duration::ZERO],
        worker_poll_interval: Duration::from_secs(1),
    });
    let state = AppState {
        pool,
        config: config.clone(),
        verifier: Arc::new(paybridge::verify::Verifier::from_config(&config)),
        http: reqwest::Client::new(),
    };
    let app = build_app(state.clone());

    // --- 1. create checkout ---------------------------------------------------
    let (status, body) = call(
        &app,
        request(
            "POST",
            "/api/v1/checkouts",
            merchant_headers(Some("order-1")),
            Some(
                json!({
                    "reference": "ORDER-1",
                    "amount": 500,
                    "currency": "ETB",
                    "items": [{"name": "Premium Ticket", "quantity": 1, "unitPrice": 500}],
                    "returnUrl": "https://merchant.test/result"
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    assert_eq!(body["status"], "created");
    assert_eq!(body["amount"], "500.00");
    assert_eq!(body["amountMinor"], 50000);
    let checkout_id = body["checkoutId"].as_str().unwrap().to_string();

    // --- 2. idempotent replay returns the same checkout ------------------------
    let (status, replay) = call(
        &app,
        request(
            "POST",
            "/api/v1/checkouts",
            merchant_headers(Some("order-1")),
            Some(json!({"reference": "ORDER-1", "amount": 500, "currency": "ETB"}).to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["checkoutId"], json!(checkout_id));

    // --- 3. select the payment method (hosted-page equivalent) ------------------
    select_method(&state, &checkout_id).await;

    // --- 4. wrong-amount reference is rejected, checkout stays pending ----------
    let (status, body) = verify(&app, &checkout_id, "mismatch-FT1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "failed");
    assert_eq!(body["reason"], "amount_mismatch");

    // --- 5. good reference succeeds ---------------------------------------------
    let (status, body) = verify(&app, &checkout_id, "FT1").await;
    assert_eq!(status, StatusCode::OK, "good ref: {body}");
    assert_eq!(body["status"], "succeeded");

    let (_, detail) = call(
        &app,
        request(
            "GET",
            &format!("/api/v1/checkouts/{checkout_id}"),
            merchant_headers(None),
            None,
        ),
    )
    .await;
    assert_eq!(detail["status"], "succeeded");
    assert_eq!(detail["transactionReference"], "FT1");
    assert_eq!(detail["paymentMethod"]["provider"], "telebirr");

    // --- 6. succeeded is terminal ------------------------------------------------
    let (status, body) = verify(&app, &checkout_id, "FT2").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "checkout_not_pending");
    assert_eq!(body["status"], "succeeded");

    // --- 7. second checkout: other failure reasons + reuse prevention ------------
    let checkout2 = create_checkout(&app, "ORDER-2", 300).await;
    select_method(&state, &checkout2).await;

    let (_, body) = verify(&app, &checkout2, "wrongwallet-FT2").await;
    assert_eq!(body["reason"], "recipient_mismatch");
    let (_, body) = verify(&app, &checkout2, "old-FT2").await;
    assert_eq!(body["reason"], "transaction_too_old");

    // The reference that paid checkout 1 cannot pay checkout 2.
    let (status, body) = verify(&app, &checkout2, "FT1").await;
    assert_eq!(status, StatusCode::CONFLICT, "reuse: {body}");
    assert_eq!(body["error"], "transaction_already_used");

    // --- 8. webhook delivery with valid signature --------------------------------
    let delivered = webhooks::deliver_due_events(&state).await;
    assert_eq!(delivered, 1, "one outbox event delivered");
    let (event_id, signature, payload) =
        tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        signature,
        webhooks::sign_payload(WEBHOOK_SECRET, payload.as_bytes()),
        "HMAC must match"
    );
    assert!(event_id.starts_with("evt_"));
    let payload_json: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload_json["event"], "checkout.payment_succeeded");
    assert_eq!(payload_json["checkoutId"], json!(checkout_id));
    assert_eq!(payload_json["reference"], "ORDER-1");
    assert_eq!(payload_json["amount"], "500.00");
    assert_eq!(payload_json["amountMinor"], 50000);
    assert_eq!(payload_json["transactionReference"], "FT1");

    let (outbox_status,): (String,) = sqlx::query_as(
        "SELECT status FROM outbox_messages WHERE aggregate_id = ? AND id = ?",
    )
    .bind(&checkout_id)
    .bind(&event_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(outbox_status, "delivered");

    // --- 9. failing endpoint: retry is scheduled, then succeeds ------------------
    fail_mode.store(true, Ordering::SeqCst);

    let checkout3 = create_checkout(&app, "ORDER-3", 200).await;
    select_method(&state, &checkout3).await;
    let (_, body) = verify(&app, &checkout3, "FT3").await;
    assert_eq!(body["status"], "succeeded");

    // First attempt: receiver returns 500.
    let delivered = webhooks::deliver_due_events(&state).await;
    assert_eq!(delivered, 1);
    let (pending, attempts): (String, i64) = sqlx::query_as(
        "SELECT status, attempts FROM outbox_messages WHERE aggregate_id = ?",
    )
    .bind(&checkout3)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!((pending.as_str(), attempts), ("pending", 1));

    // Receiver recovers; retry succeeds.
    fail_mode.store(false, Ordering::SeqCst);
    let delivered = webhooks::deliver_due_events(&state).await;
    assert_eq!(delivered, 1);
    let (delivered_status, attempts): (String, i64) = sqlx::query_as(
        "SELECT status, attempts FROM outbox_messages WHERE aggregate_id = ?",
    )
    .bind(&checkout3)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!((delivered_status.as_str(), attempts), ("delivered", 2));
}

#[derive(Clone)]
struct ReceiverState {
    tx: tokio::sync::mpsc::Sender<(String, String, String)>,
    fail: Arc<AtomicBool>,
}

async fn handle_webhook(
    State(st): State<ReceiverState>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    let event_id = headers
        .get("x-paybridge-event-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let signature = headers
        .get("x-paybridge-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let _ = st.tx.send((event_id, signature, body)).await;
    if st.fail.load(Ordering::SeqCst) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

async fn seed(pool: &SqlitePool, endpoint_url: &str) {
    let now = paybridge::ids::now_iso();
    sqlx::query("INSERT INTO merchants (id, name, status, created_at) VALUES (?, 'Acme (test)', 'active', ?)")
        .bind(MERCHANT)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO merchant_api_keys (id, merchant_id, prefix, key_hash, created_at) VALUES ('key_test', ?, ?, ?, ?)",
    )
    .bind(MERCHANT)
    .bind(&API_KEY[..12])
    .bind(sha256_hex(API_KEY))
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO merchant_payment_methods \
         (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at) \
         VALUES (?, ?, 'telebirr', 'Telebirr', '+251900000000', 'Open the app|Send the money|Copy the reference', 'active', ?)",
    )
    .bind(METHOD)
    .bind(MERCHANT)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO webhook_endpoints (id, merchant_id, url, secret, status, created_at) VALUES ('wh_test', ?, ?, ?, 'active', ?)",
    )
    .bind(MERCHANT)
    .bind(endpoint_url)
    .bind(WEBHOOK_SECRET)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
}

fn merchant_headers(idempotency_key: Option<&str>) -> Headers {
    let mut headers: Headers = vec![
        ("authorization".to_string(), format!("Bearer {API_KEY}")),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    if let Some(key) = idempotency_key {
        headers.push(("idempotency-key".to_string(), key.to_string()));
    }
    headers
}

fn request(method: &str, uri: &str, headers: Headers, body: Option<String>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::from(body.unwrap_or_default())).unwrap()
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn create_checkout(app: &Router, reference: &str, amount: i64) -> String {
    let (status, body) = call(
        app,
        request(
            "POST",
            "/api/v1/checkouts",
            merchant_headers(None),
            Some(json!({"reference": reference, "amount": amount, "currency": "ETB"}).to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["checkoutId"].as_str().unwrap().to_string()
}

async fn select_method(state: &AppState, checkout_id: &str) {
    sqlx::query("UPDATE checkouts SET selected_method_id = ?, status = 'pending' WHERE id = ?")
        .bind(METHOD)
        .bind(checkout_id)
        .execute(&state.pool)
        .await
        .unwrap();
}

async fn verify(app: &Router, checkout_id: &str, reference: &str) -> (StatusCode, Value) {
    call(
        app,
        request(
            "POST",
            &format!("/api/v1/checkouts/{checkout_id}/verify"),
            vec![("content-type".to_string(), "application/json".to_string())],
            Some(json!({"transactionReference": reference}).to_string()),
        ),
    )
    .await
}
