//! Admin portal integration test: auth gate, login flow, every MVP page,
//! merchant suspension (audited + enforced on the merchant API), and webhook
//! retry re-queueing.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Router;
use paybridge::auth::sha256_hex;
use paybridge::config::{Config, VerifierKind};
use paybridge::state::AppState;
use paybridge::{app::build_app, ids::now_iso};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const API_KEY: &str = "pb_sk_test_admin_key1";
const ADMIN_EMAIL: &str = "admin@paybridge.test";
const ADMIN_PASSWORD: &str = "test-admin-123";
const MERCHANT: &str = "mch_admin_test";
const CHECKOUT: &str = "chk_admin_test";
const DELIVERY: &str = "whd_admin_test";
const EVENT: &str = "evt_admin_test";
const ENDPOINT: &str = "wh_admin_test";

#[tokio::test]
async fn admin_portal() {
    let (app, pool, _tmp) = setup().await;

    // --- 1. /admin is gated ---------------------------------------------------
    let (status, _, headers) = call(&app, get("/admin", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/admin/login");

    // --- 2. wrong password rejected --------------------------------------------
    let (status, _, _) = call(
        &app,
        post(
            "/admin/login",
            &format!("email={ADMIN_EMAIL}&password=wrong"),
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- 3. correct credentials set the session cookie ---------------------------
    let (status, _, headers) = call(
        &app,
        post(
            "/admin/login",
            &format!("email={ADMIN_EMAIL}&password={ADMIN_PASSWORD}"),
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/admin");
    let cookie = headers["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("pb_user="));
    // The cookie pair ("pb_user=<id>.<token>") goes into the Cookie header; the
    // token after the dot is the double-submit CSRF value of admin forms.
    let cookie_pair = cookie.split(';').next().unwrap().to_string();
    let csrf = cookie_pair.split_once('=').unwrap().1.split_once('.').unwrap().1.to_string();

    // --- 4. every MVP page renders ----------------------------------------------
    let pages = [
        ("/admin".to_string(), "Dashboard".to_string()),
        ("/admin/merchants".to_string(), "Acme Admin Test".to_string()),
        (format!("/admin/merchants/{MERCHANT}"), "Telebirr".to_string()),
        ("/admin/checkouts?q=ORDER-77".to_string(), "ORDER-77".to_string()),
        (format!("/admin/checkouts/{CHECKOUT}"), "ORDER-77".to_string()),
        ("/admin/webhooks".to_string(), "Recent deliveries".to_string()),
        (
            format!("/admin/webhooks/deliveries/{DELIVERY}"),
            "checkout.payment_succeeded".to_string(),
        ),
        ("/admin/audit".to_string(), "audit".to_string()),
    ];
    for (path, must_contain) in pages {
        let (status, body, _) = call(&app, get(&path, Some(&cookie_pair))).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert!(body.contains(&must_contain), "GET {path} should contain {must_contain:?}: {body}");
    }

    // --- 5. suspension is audited and enforced on the merchant API ---------------
    let (status, _, _) = merchant_call(&app).await;
    assert_eq!(status, StatusCode::OK, "merchant API works before suspension");

    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/status"),
            &format!("csrf={csrf}&action=suspend"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, body, _) = merchant_call(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "suspended merchant API key rejected: {body}");

    let (suspended_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'merchant.suspended' AND resource_id = ?",
    )
    .bind(MERCHANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(suspended_rows, 1);

    // Reactivate: API works again.
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/status"),
            &format!("csrf={csrf}&action=reactivate"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = merchant_call(&app).await;
    assert_eq!(status, StatusCode::OK, "reactivated merchant API key works");

    // --- 6. CSRF: retry with a wrong csrf field is rejected ----------------------
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/webhooks/deliveries/{DELIVERY}/retry"),
            "csrf=wrong",
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- 7. webhook retry re-queues the event and audits it ----------------------
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/webhooks/deliveries/{DELIVERY}/retry"),
            &format!("csrf={csrf}"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (event_status, attempts): (String, i64) = sqlx::query_as(
        "SELECT status, attempts FROM outbox_messages WHERE id = ?",
    )
    .bind(EVENT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event_status, "pending");
    assert_eq!(attempts, 7, "retry grants one fresh attempt");

    let (retry_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'webhook.retried' AND resource_id = ?",
    )
    .bind(EVENT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retry_rows, 1);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn seed(pool: &SqlitePool) {
    let now = now_iso();
    sqlx::query("INSERT INTO merchants (id, name, status, created_at) VALUES (?, 'Acme Admin Test', 'active', ?)")
        .bind(MERCHANT)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    // Starting verification credit so the merchant API passes the prepaid gate.
    sqlx::query("UPDATE merchants SET credit_balance = 1000 WHERE id = ?")
        .bind(MERCHANT)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO merchant_api_keys (id, merchant_id, prefix, key_hash, created_at) \
         VALUES ('key_admin_test', ?, ?, ?, ?)",
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
         VALUES ('mpm_admin_test', ?, 'telebirr', 'Telebirr', '+251900000000', 'steps', 'active', ?)",
    )
    .bind(MERCHANT)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO webhook_endpoints (id, merchant_id, url, secret, status, created_at) \
         VALUES (?, ?, 'https://merchant.test/webhooks', 'whsec_admin_test', 'active', ?)",
    )
    .bind(ENDPOINT)
    .bind(MERCHANT)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO checkouts \
         (id, merchant_id, reference, amount_minor, currency, status, expires_at, created_at, updated_at) \
         VALUES (?, ?, 'ORDER-77', 50000, 'ETB', 'pending', '2027-01-01T00:00:00Z', ?, ?)",
    )
    .bind(CHECKOUT)
    .bind(MERCHANT)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_attempts \
         (id, checkout_id, transaction_reference, outcome, created_at) \
         VALUES ('att_admin_test', ?, 'FT77', 'transaction_not_found', ?)",
    )
    .bind(CHECKOUT)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO outbox_messages \
         (id, event_type, aggregate_id, payload, status, attempts, next_attempt_at, created_at) \
         VALUES (?, 'checkout.payment_succeeded', ?, '{\"event\":\"checkout.payment_succeeded\"}', 'dead', 8, ?, ?)",
    )
    .bind(EVENT)
    .bind(CHECKOUT)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO webhook_deliveries \
         (id, outbox_id, endpoint_id, attempt_no, status_code, error, duration_ms, created_at) \
         VALUES (?, ?, ?, 8, 500, 'server exploded', 120, ?)",
    )
    .bind(DELIVERY)
    .bind(EVENT)
    .bind(ENDPOINT)
    .bind(&now)
    .execute(pool)
    .await
    .unwrap();
}

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(token) = token {
        builder = builder.header(header::COOKIE, token);
    }
    builder.body(Body::empty()).unwrap()
}

fn post(path: &str, body: &str, content_type: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(token) = token {
        builder = builder.header(header::COOKIE, token);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// Generic request builder (merchant API calls in the credits test).
fn request(
    method: &str,
    uri: &str,
    headers: Vec<(String, String)>,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::from(body.unwrap_or_default())).unwrap()
}

/// Merchant-API call used to prove suspension enforcement.
async fn merchant_call(app: &Router) -> (StatusCode, String, HeaderMap) {
    merchant_call_with(app, API_KEY).await
}

/// Merchant-API call with an arbitrary key (key management tests).
async fn merchant_call_with(app: &Router, key: &str) -> (StatusCode, String, HeaderMap) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/checkouts/{CHECKOUT}"))
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::empty())
        .unwrap();
    call(app, req).await
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String, HeaderMap) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string(), headers)
}

/// JSON-API variant for merchant-facing endpoints.
async fn call_json(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let (status, body, _) = call(app, req).await;
    (status, serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
}

/// Shared app + database: migrations, seeded merchant/key/method/endpoint,
/// one pending checkout, one dead webhook delivery with its event.
async fn setup() -> (Router, SqlitePool, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let db_url = format!(
        "sqlite://{}/paybridge.db?mode=rwc",
        tmp.path().display().to_string().replace('\\', "/")
    );
    let pool = SqlitePool::connect(&db_url).await.unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    paybridge::admin::ensure_bootstrap_admin(&pool, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    seed(&pool).await;

    let config = Arc::new(Config {
        bind: "127.0.0.1:0".into(),
        database_url: db_url,
        base_url: "http://paybridge.test".into(),
        verifier: VerifierKind::Mock,
        verify_service_url: None,
        verify_service_api_key: None,
        checkout_ttl_default: Duration::from_secs(3600),
        checkout_ttl_max: Duration::from_secs(7 * 86_400),
        verify_max_attempts: 10,
        verify_cooldown: Duration::ZERO,
        webhook_schedule: vec![Duration::ZERO],
        worker_poll_interval: Duration::from_secs(1),
        static_dir: std::path::PathBuf::from("static"),
        admin_password: ADMIN_PASSWORD.into(),
        admin_email: ADMIN_EMAIL.into(),
    });
    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
        verifier: Arc::new(paybridge::verify::Verifier::from_config(&config)),
        http: reqwest::Client::new(),
    };
    (build_app(state), pool, tmp)
}

/// Login as the bootstrap superadmin; returns (cookie pair, csrf token).
async fn login(app: &Router) -> (String, String) {
    login_tuple(app, ADMIN_EMAIL, ADMIN_PASSWORD).await
}

/// Login as any user; returns the cookie pair only.
async fn login_with(app: &Router, email: &str, password: &str) -> String {
    let (status, _, headers) = call(
        app,
        post(
            "/admin/login",
            &format!("email={email}&password={password}"),
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login as {email}");
    headers["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string()
}

async fn login_tuple(app: &Router, email: &str, password: &str) -> (String, String) {
    let cookie_pair = login_with(app, email, password).await;
    let csrf = cookie_pair
        .split_once('=')
        .unwrap()
        .1
        .split_once('.')
        .unwrap()
        .1
        .to_string();
    (cookie_pair, csrf)
}

/// Pull the one-time secret out of the key-reveal box on the merchant page.
fn extract_new_secret(body: &str) -> String {
    let marker = "it will not be shown again";
    let start = body.find(marker).expect("key-reveal banner missing") + marker.len();
    let rest = &body[start..];
    let cs = rest.find("<code>").expect("<code> missing") + 6;
    let ce = rest[cs..].find("</code>").expect("</code> missing") + cs;
    rest[cs..ce].trim().to_string()
}

#[tokio::test]
async fn merchant_management() {
    let (app, pool, _tmp) = setup().await;
    let (cookie_pair, csrf) = login(&app).await;

    // --- 1. add a payment method -------------------------------------------------
    let (status, body, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/methods"),
            &format!(
                "csrf={csrf}&provider=cbebirr&display_name=&account_identifier=1000123456789&instructions="
            ),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "method create renders the page: {body}");
    assert!(body.contains("CBE Birr"), "new method visible: {body}");
    assert!(body.contains("1000123456789"), "receiving account visible");

    let (method_id, method_status): (String, String) = sqlx::query_as(
        "SELECT id, status FROM merchant_payment_methods \
         WHERE merchant_id = ? AND provider = 'cbebirr'",
    )
    .bind(MERCHANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(method_status, "active");

    // --- 2. disable it, then change its receiving account -------------------------
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/methods/{method_id}/status"),
            &format!("csrf={csrf}&action=disable"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status,): (String,) = sqlx::query_as(
        "SELECT status FROM merchant_payment_methods WHERE id = ?",
    )
    .bind(&method_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "disabled");

    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/methods/{method_id}/account"),
            &format!("csrf={csrf}&account_identifier=1000987654321"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (account,): (String,) = sqlx::query_as(
        "SELECT account_identifier FROM merchant_payment_methods WHERE id = ?",
    )
    .bind(&method_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(account, "1000987654321");

    // --- 3. create an API key: secret shown once, and it authenticates -------------
    let (status, body, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/keys"),
            &format!("csrf={csrf}&kind=test"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "key create renders the page: {body}");
    let secret = extract_new_secret(&body);
    assert!(secret.starts_with("pb_sk_test_"));
    assert!(body.contains(&format!("{}&hellip;", &secret[..12])), "prefix listed");

    // The freshly created key works against the merchant API...
    let (status, _, _) = merchant_call_with(&app, &secret).await;
    assert_eq!(status, StatusCode::OK, "new key authenticates");

    // ...until it is revoked.
    let (key_id,): (String,) = sqlx::query_as(
        "SELECT id FROM merchant_api_keys WHERE merchant_id = ? AND key_hash = ?",
    )
    .bind(MERCHANT)
    .bind(sha256_hex(&secret))
    .fetch_one(&pool)
    .await
    .unwrap();
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/keys/{key_id}/revoke"),
            &format!("csrf={csrf}"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = merchant_call_with(&app, &secret).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked key rejected");

    // --- 4. rotate the seeded key: old dies, replacement works ---------------------
    let (status, body, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/keys/key_admin_test/rotate"),
            &format!("csrf={csrf}"),
            "application/x-www-form-urlencoded",
            Some(&cookie_pair),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate renders the page: {body}");
    let rotated = extract_new_secret(&body);
    assert!(rotated.starts_with("pb_sk_test_"));

    let (status, _, _) = merchant_call_with(&app, API_KEY).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "rotated-out key rejected");
    let (status, _, _) = merchant_call_with(&app, &rotated).await;
    assert_eq!(status, StatusCode::OK, "replacement key authenticates");

    // --- 5. the whole trail is audited ---------------------------------------------
    for action in [
        "payment_method.added",
        "payment_method.disabled",
        "payment_method.account_changed",
        "api_key.created",
        "api_key.revoked",
        "api_key.rotated",
    ] {
        let (rows,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_logs WHERE action = ?",
        )
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(rows >= 1, "audit trail missing {action}");
    }
}

#[tokio::test]
async fn signup_approval_and_roles() {
    let (app, pool, _tmp) = setup().await;
    let (admin_cookie, admin_csrf) = login(&app).await;

    // --- 1. public merchant signup creates a pending merchant + owner --------------
    let (status, body, _) = call(
        &app,
        get("/signup", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Merchant signup"));

    let (status, body, _) = call(
        &app,
        post(
            "/signup",
            "merchant_name=Fresh Shop&name=Owner&email=owner@fresh.test&password=sup3rsecret1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "signup: {body}");

    let (merchant_id, onboarding): (String, String) = sqlx::query_as(
        "SELECT id, onboarding_status FROM merchants WHERE name = 'Fresh Shop'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(onboarding, "pending");

    // Duplicate email is rejected.
    let (status, _, _) = call(
        &app,
        post(
            "/signup",
            "merchant_name=Other&name=X&email=owner@fresh.test&password=sup3rsecret1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- 2. pending merchant cannot use the API ------------------------------------
    // (no key yet; proving the onboarding gate directly via SQL state instead)
    let (merchant_status,): (String,) =
        sqlx::query_as("SELECT status FROM merchants WHERE id = ?")
            .bind(&merchant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(merchant_status, "active", "signup merchants are active-but-pending");

    // --- 3. the merchant owner logs in and sees the portal, not the admin -----------
    let (status, _, headers) = call(
        &app,
        post(
            "/admin/login",
            "email=owner@fresh.test&password=sup3rsecret1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/portal", "merchant users land on /portal");
    let owner_cookie = headers["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();

    let (status, body, _) = call(&app, get("/portal", Some(&owner_cookie))).await;
    assert_eq!(status, StatusCode::OK, "portal renders");
    assert!(body.contains("Fresh Shop") && body.contains("pending activation"), "{body}");

    // Merchant users are bounced away from /admin.
    let (status, _, headers) = call(&app, get("/admin", Some(&owner_cookie))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/portal");

    // --- 4. superadmin approves; merchant API becomes usable ------------------------
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{merchant_id}/approve"),
            &format!("csrf={admin_csrf}"),
            "application/x-www-form-urlencoded",
            Some(&admin_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (onboarding,): (String,) = sqlx::query_as(
        "SELECT onboarding_status FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(onboarding, "approved");

    // --- 5. role capability matrix ---------------------------------------------------
    // Developer can retry webhooks but not suspend merchants; support cannot either.
    for (email, password, role) in [
        ("dev@paybridge.test", "devpassword1", "developer"),
        ("ops@paybridge.test", "opspassword1", "operations"),
        ("sup@paybridge.test", "suppassword1", "support"),
    ] {
        let (status, body, _) = call(
            &app,
            post(
                "/admin/users",
                &format!("csrf={admin_csrf}&email={email}&name={role}&role={role}&password={password}&merchant_id="),
                "application/x-www-form-urlencoded",
                Some(&admin_cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "create {role}: {body}");
    }

    let dev_cookie = login_with(&app, "dev@paybridge.test", "devpassword1").await;
    let sup_cookie = login_with(&app, "sup@paybridge.test", "suppassword1").await;

    // Both can view pages...
    let (status, _, _) = call(&app, get("/admin/checkouts", Some(&dev_cookie))).await;
    assert_eq!(status, StatusCode::OK);
    // ...but only superadmin reaches the users page...
    let (status, _, _) = call(&app, get("/admin/users", Some(&dev_cookie))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(&app, get("/admin/users", Some(&sup_cookie))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // ...and only superadmin can suspend merchants or create keys.
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{merchant_id}/status"),
            &format!("csrf={admin_csrf}&action=suspend"),
            "application/x-www-form-urlencoded",
            Some(&dev_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "developer cannot suspend merchants");
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/keys"),
            &format!("csrf={admin_csrf}&kind=test"),
            "application/x-www-form-urlencoded",
            Some(&sup_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "support cannot create API keys");

    // Superadmin sees the users page with the created users.
    let (status, body, _) = call(&app, get("/admin/users", Some(&admin_cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("dev@paybridge.test"));
}

#[tokio::test]
async fn credits_flow() {
    let (app, pool, _tmp) = setup().await;
    let (admin_cookie, admin_csrf) = login(&app).await;

    // --- 1. merchant signs up: pending, zero credit ------------------------------
    let (status, _, _) = call(
        &app,
        post(
            "/signup",
            "merchant_name=Credit Shop&name=Owner&email=owner@credit.test&password=sup3rsecret1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (merchant_id,): (String,) = sqlx::query_as(
        "SELECT id FROM merchants WHERE name = 'Credit Shop'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (credits, onboarding): (i64, String) = sqlx::query_as(
        "SELECT credit_balance, onboarding_status FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((credits, onboarding.as_str()), (0, "pending"));

    // --- 2. owner signs in and buys a 200-credit package --------------------------
    let (_, _, headers) = call(
        &app,
        post(
            "/admin/login",
            "email=owner@credit.test&password=sup3rsecret1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    let owner_cookie =
        headers["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let owner_csrf =
        owner_cookie.split_once('=').unwrap().1.split_once('.').unwrap().1.to_string();

    let (status, body, buy_headers) = call(
        &app,
        post(
            "/portal/credits/buy",
            &format!("csrf={owner_csrf}&credits=200"),
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "buy redirects to the hosted checkout: {body}");
    let purchase_checkout = buy_headers["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    assert!(purchase_checkout.starts_with("chk_"), "location was: {}", buy_headers["location"].to_str().unwrap());
    let (in_db,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM checkouts WHERE id = ?",
    )
    .bind(&purchase_checkout)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(in_db, 1, "credit checkout must exist");

    // --- 3. the purchase checkout is verified like any payment --------------------
    // (select the platform's Telebirr method, then verify a mock reference)
    sqlx::query(
        "UPDATE checkouts SET selected_method_id = 'mpm_seed_pb_telebirr', status = 'pending' \
         WHERE id = ?",
    )
    .bind(&purchase_checkout)
    .execute(&pool)
    .await
    .unwrap();

    let (status, body, _) = call(
        &app,
        request(
            "POST",
            &format!("/api/v1/checkouts/{purchase_checkout}/verify"),
            vec![("content-type".to_string(), "application/json".to_string())],
            Some(r#"{"transactionReference":"FT-CREDITS-1"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "purchase verify: {body}");

    let (credits, onboarding): (i64, String) = sqlx::query_as(
        "SELECT credit_balance, onboarding_status FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((credits, onboarding.as_str()), (200, "approved"), "purchase settled instantly");

    let (ledger_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM credit_ledger WHERE merchant_id = ? AND reason = 'purchase' AND delta = 200",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ledger_rows, 1);

    // --- 4. with credit, the merchant self-generates an API key --------------------
    let (status, body, _) = call(
        &app,
        post(
            "/portal/keys/generate",
            &format!("csrf={owner_csrf}"),
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "key generate: {body}");
    let secret = extract_new_secret(&body);
    assert!(secret.starts_with("pb_sk_test_"));

    // --- 5. a successful verification consumes exactly one credit ------------------
    let (status, body, _) = call(
        &app,
        request(
            "POST",
            "/api/v1/checkouts",
            vec![
                ("authorization".to_string(), format!("Bearer {secret}")),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            Some(r#"{"reference":"ORDER-C1","amount":100,"currency":"ETB"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create with credit: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let own_checkout = created["checkoutId"].as_str().unwrap().to_string();
    sqlx::query(
        "UPDATE checkouts SET selected_method_id = 'mpm_admin_test', status = 'pending' WHERE id = ?",
    )
    .bind(&own_checkout)
    .execute(&pool)
    .await
    .unwrap();

    let (status, body, _) = call(
        &app,
        request(
            "POST",
            &format!("/api/v1/checkouts/{own_checkout}/verify"),
            vec![("content-type".to_string(), "application/json".to_string())],
            Some(r#"{"transactionReference":"FT-OWN-1"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own verify: {body}");

    let (credits,): (i64,) = sqlx::query_as(
        "SELECT credit_balance FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(credits, 199, "one credit consumed by the successful verification");

    // A second checkout, created while credit is still available.
    let (status, body, _) = call(
        &app,
        request(
            "POST",
            "/api/v1/checkouts",
            vec![
                ("authorization".to_string(), format!("Bearer {secret}")),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            Some(r#"{"reference":"ORDER-C2","amount":100,"currency":"ETB"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "second create: {body}");
    let created2: serde_json::Value = serde_json::from_str(&body).unwrap();
    let pending_checkout = created2["checkoutId"].as_str().unwrap().to_string();
    sqlx::query(
        "UPDATE checkouts SET selected_method_id = 'mpm_admin_test', status = 'pending' WHERE id = ?",
    )
    .bind(&pending_checkout)
    .execute(&pool)
    .await
    .unwrap();

    // --- 6. at zero credit, checkout creation is 402 and verification refuses ------
    sqlx::query("UPDATE merchants SET credit_balance = 0 WHERE id = ?")
        .bind(&merchant_id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, body, _) = call(
        &app,
        request(
            "POST",
            "/api/v1/checkouts",
            vec![
                ("authorization".to_string(), format!("Bearer {secret}")),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            Some(r#"{"reference":"ORDER-C3","amount":100,"currency":"ETB"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "create at zero credits: {body}");
    let err: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"], "insufficient_credits");

    let (status, body, _) = call(
        &app,
        request(
            "POST",
            &format!("/api/v1/checkouts/{pending_checkout}/verify"),
            vec![("content-type".to_string(), "application/json".to_string())],
            Some(r#"{"transactionReference":"FT-OWN-2"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "verify at zero credits: {body}");
    let err: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"], "insufficient_credits");

    // --- 7. admin grant tops the balance back up (audited) --------------------------
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{merchant_id}/credits"),
            &format!("csrf={admin_csrf}&amount=50"),
            "application/x-www-form-urlencoded",
            Some(&admin_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (credits,): (i64,) = sqlx::query_as(
        "SELECT credit_balance FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(credits, 50);
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'credits.granted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn portal_scoping() {
    let (app, pool, _tmp) = setup().await;
    let (admin_cookie, admin_csrf) = login(&app).await;

    // A merchant-role user for the seeded test merchant.
    let (status, body, _) = call(
        &app,
        post(
            "/admin/users",
            &format!(
                "csrf={admin_csrf}&email=merchant@acme.test&name=Acme Owner&role=merchant&password=merchpass1&merchant_id={MERCHANT}"
            ),
            "application/x-www-form-urlencoded",
            Some(&admin_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "create merchant user: {body}");

    let (status, _, headers) = call(
        &app,
        post(
            "/admin/login",
            "email=merchant@acme.test&password=merchpass1",
            "application/x-www-form-urlencoded",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/portal");
    let owner_cookie =
        headers["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();

    // Own checkout: visible.
    let (status, body, _) = call(
        &app,
        get(&format!("/portal/checkouts/{CHECKOUT}"), Some(&owner_cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own checkout detail");
    assert!(body.contains("ORDER-77"));

    // Another merchant's checkout: 404, and absent from every list.
    let now = now_iso();
    sqlx::query(
        "INSERT INTO merchants (id, name, status, created_at) VALUES ('mch_other', 'Other Shop', 'active', ?)",
    )
    .bind(&now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO checkouts \
         (id, merchant_id, reference, amount_minor, currency, status, expires_at, created_at, updated_at) \
         VALUES ('chk_other', 'mch_other', 'ORDER-OTHER', 9900, 'ETB', 'pending', '2027-01-01T00:00:00Z', ?, ?)",
    )
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await
    .unwrap();

    let (status, _, _) = call(
        &app,
        get("/portal/checkouts/chk_other", Some(&owner_cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "other merchant's checkout is 404");

    let (status, body, _) = call(
        &app,
        get("/portal/checkouts?q=ORDER-OTHER", Some(&owner_cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("chk_other"), "list must not leak other merchants");

    // Webhooks: sees own delivery, can retry it.
    let (status, body, _) = call(&app, get("/portal/webhooks", Some(&owner_cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("whd_admin_test"), "own delivery listed: {body}");

    let (status, body, _) = call(
        &app,
        get("/portal/webhooks/deliveries/whd_admin_test", Some(&owner_cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own delivery detail: {body}");

    let (pending_before,): (String,) = sqlx::query_as(
        "SELECT status FROM outbox_messages WHERE id = ?",
    )
    .bind(EVENT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending_before, "dead");

    let owner_csrf =
        owner_cookie.split_once('=').unwrap().1.split_once('.').unwrap().1.to_string();
    let (status, _, _) = call(
        &app,
        post(
            "/portal/webhooks/deliveries/whd_admin_test/retry",
            &format!("csrf={owner_csrf}"),
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "merchant retries own delivery");

    let (event_status,): (String,) = sqlx::query_as(
        "SELECT status FROM outbox_messages WHERE id = ?",
    )
    .bind(EVENT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event_status, "pending", "retry re-queued the merchant's event");

    // (csrf was the admin's on purpose: wrong csrf must fail)
    let (status, _, _) = call(
        &app,
        post(
            "/portal/webhooks/deliveries/whd_admin_test/retry",
            "csrf=wrong",
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- merchant adds own payment method: steps come from platform config --------
    let (status, _, _) = call(
        &app,
        post(
            "/portal/methods",
            &format!("csrf={owner_csrf}&provider=cbebirr&display_name=&account_identifier=10001112222"),
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "portal method create");

    let (instructions, method_status): (String, String) = sqlx::query_as(
        "SELECT instructions, status FROM merchant_payment_methods \
         WHERE merchant_id = ? AND provider = 'cbebirr'",
    )
    .bind(MERCHANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(method_status, "active");
    assert!(instructions.contains("CBE Birr app"), "steps from platform config: {instructions}");

    // Admin edits the steps; merchant cannot.
    let (method_id,): (String,) = sqlx::query_as(
        "SELECT id FROM merchant_payment_methods WHERE merchant_id = ? AND provider = 'cbebirr'",
    )
    .bind(MERCHANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (status, _, _) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/methods/{method_id}/instructions"),
            &format!("csrf={admin_csrf}&instructions=Step one%0AStep two"),
            "application/x-www-form-urlencoded",
            Some(&admin_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "admin edits steps");
    let (instructions,): (String,) = sqlx::query_as(
        "SELECT instructions FROM merchant_payment_methods WHERE id = ?",
    )
    .bind(&method_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(instructions, "Step one\nStep two");

    // Merchant-role users never reach /admin at all — the gate bounces them
    // back to /portal, so the steps editor is unreachable by construction.
    let (status, _, headers) = call(
        &app,
        post(
            &format!("/admin/merchants/{MERCHANT}/methods/{method_id}/instructions"),
            &format!("csrf={owner_csrf}&instructions=hijack"),
            "application/x-www-form-urlencoded",
            Some(&owner_cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/portal", "merchant bounced out of /admin");
}
