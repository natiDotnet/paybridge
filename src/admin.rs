//! Admin portal (MVP): dashboard, merchants, checkouts, webhooks, audit log.
//! Single shared admin password from `PAYBRIDGE_ADMIN_PASSWORD`; the session
//! is an HMAC cookie and forms double-submit it as CSRF. Roles and merchant
//! self-service are deliberately out of scope for now.

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use askama::Template;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;

use crate::db;
use crate::db::Db;
use crate::db::Pool;
use crate::ids::{new_id, now_iso};
use crate::money::format_minor;
use crate::state::AppState;

const USER_COOKIE: &str = "pb_user";
const SESSION_DOMAIN: &str = "paybridge-user-session-v1";
const PBKDF2_ITERATIONS: u32 = 20_000;

/// The authenticated identity, inserted into request extensions by the
/// session middleware and consumed by handlers for capability checks.
#[derive(Clone)]
pub struct SessionInfo {
    pub user: CurrentUser,
    /// Session token (also the double-submit CSRF value of user forms).
    pub token: String,
}

#[derive(Clone)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
    pub role: String,
    pub merchant_id: Option<String>,
}

/// Mutation capabilities from the permission matrix; every platform role has
/// view access to the operational pages.
pub enum Cap {
    ManageMerchants,
    ManageApiKeys,
    ManageWebhooks,
    ManageUsers,
}

pub fn can(role: &str, cap: &Cap) -> bool {
    match role {
        "superadmin" => true,
        "operations" => matches!(cap, Cap::ManageWebhooks),
        "developer" => matches!(cap, Cap::ManageWebhooks | Cap::ManageApiKeys),
        // "support" and unknown roles are view-only.
        _ => false,
    }
}

// --- passwords ---------------------------------------------------------------

/// Bare PBKDF2-HMAC-SHA256 (single block); we only need password verification
/// and don't want an extra crypto dependency for this MVP.
fn pbkdf2_hmac_sha256(password: &str, salt: &str, iterations: u32) -> [u8; 32] {
    let key = password.as_bytes();
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt.as_bytes());
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u: [u8; 32] = hmac_sha256(key, &block);
    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha256(key, &u);
        for (ti, ui) in t.iter_mut().zip(u.iter()) {
            *ti ^= *ui;
        }
    }
    t
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hash_password(password: &str) -> String {
    let salt = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
    format!(
        "pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${}",
        hex::encode(pbkdf2_hmac_sha256(password, &salt, PBKDF2_ITERATIONS))
    )
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let Ok(iterations) = parts[1].parse::<u32>() else { return false };
    if iterations == 0 || iterations > 2_000_000 {
        return false;
    }
    let Ok(expected) = hex::decode(parts[3]) else { return false };
    ct_eq(&pbkdf2_hmac_sha256(password, parts[2], iterations), &expected)
}

/// Create the first superadmin from env config if none exists yet.
pub async fn ensure_bootstrap_admin(pool: &Pool, email: &str, password: &str) {
    let (count,): (i64,) = match db::query_as(
        "SELECT COUNT(*) FROM users WHERE role = 'superadmin'",
    )
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = %e, "bootstrap admin check failed");
            return;
        }
    };
    if count > 0 {
        return;
    }
    let _ = db::query(
        "INSERT INTO users (id, email, name, password_hash, role, merchant_id, status, created_at) \
         VALUES (?, ?, 'Platform Admin', ?, 'superadmin', NULL, 'active', ?) ON CONFLICT DO NOTHING",
    )
    .bind(new_id("usr"))
    .bind(email)
    .bind(hash_password(password))
    .bind(now_iso())
    .execute(pool)
    .await;
    tracing::info!(email, "bootstrapped superadmin user");
}

// --- sessions ----------------------------------------------------------------

/// Session token bound to the user's current password hash: changing a
/// password (or disabling the user) invalidates their sessions.
fn session_token(password_hash: &str, user_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(password_hash.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(format!("{SESSION_DOMAIN}:{user_id}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time byte equality (session cookie, password, CSRF compares).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split("; ")
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('=').map(str::to_owned))
}

async fn session_info(state: &AppState, headers: &HeaderMap) -> Option<SessionInfo> {
    let raw = read_cookie(headers, USER_COOKIE)?;
    let (user_id, token) = raw.split_once('.')?;
    let (password_hash, email, role, merchant_id): (String, String, String, Option<String>) =
        db::query_as(
            "SELECT password_hash, email, role, merchant_id FROM users \
             WHERE id = ? AND status = 'active'",
        )
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()?;
    let expected = session_token(&password_hash, user_id);
    if !ct_eq(token.as_bytes(), expected.as_bytes()) {
        return None;
    }
    Some(SessionInfo {
        user: CurrentUser { id: user_id.to_string(), email, role, merchant_id },
        token: expected,
    })
}

/// Gate for /admin: requires a session; merchant users are sent to /portal.
pub async fn require_admin(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(session) = session_info(&state, req.headers()).await else {
        return Redirect::to("/admin/login").into_response();
    };
    if session.user.role == "merchant" {
        return Redirect::to("/portal").into_response();
    }
    req.extensions_mut().insert(session);
    next.run(req).await
}

/// Gate for /portal: merchant-role users only.
pub async fn require_merchant(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(session) = session_info(&state, req.headers()).await else {
        return Redirect::to("/admin/login").into_response();
    };
    if session.user.role != "merchant" {
        return Redirect::to("/admin").into_response();
    }
    req.extensions_mut().insert(session);
    next.run(req).await
}

/// Double-submit CSRF: user forms carry the session token as a hidden field.
fn csrf_ok(session: &SessionInfo, submitted: &str) -> bool {
    !submitted.is_empty() && ct_eq(submitted.as_bytes(), session.token.as_bytes())
}

/// Best-effort client IP for the audit trail (in prod we sit behind TLS/proxy,
/// so the forwarding headers carry the meaningful values).
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
}

async fn audit(
    pool: &Pool,
    actor: &str,
    ip: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: &str,
    metadata: Option<String>,
) {
    let _ = db::query(
        "INSERT INTO audit_logs (id, actor, action, resource, resource_id, ip, metadata, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(new_id("aud"))
    .bind(actor)
    .bind(action)
    .bind(resource)
    .bind(resource_id)
    .bind(ip)
    .bind(metadata)
    .bind(now_iso())
    .execute(pool)
    .await;
}

fn page(status: StatusCode, template: impl askama::Template) -> Response {
    match template.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "admin page failed to render").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// `/admin/login` and `/signup` are public; everything else sits behind
/// `require_admin` (platform roles) with per-action capability checks.
pub fn router(state: AppState) -> Router<AppState> {
    let protected = Router::new()
        .route("/", get(dashboard))
        .route("/merchants", get(merchants))
        .route("/merchants/{merchant_id}", get(merchant_detail))
        .route("/merchants/{merchant_id}/status", post(merchant_status))
        .route("/merchants/{merchant_id}/approve", post(merchant_approve))
        .route("/merchants/{merchant_id}/credits", post(credits_grant))
        .route("/merchants/{merchant_id}/methods", post(method_create))
        .route(
            "/merchants/{merchant_id}/methods/{method_id}/status",
            post(method_status),
        )
        .route(
            "/merchants/{merchant_id}/methods/{method_id}/account",
            post(method_account),
        )
        .route(
            "/merchants/{merchant_id}/methods/{method_id}/name",
            post(method_name),
        )
        .route(
            "/merchants/{merchant_id}/methods/{method_id}/instructions",
            post(method_instructions),
        )
        .route("/merchants/{merchant_id}/keys", post(key_create))
        .route("/merchants/{merchant_id}/keys/{key_id}/revoke", post(key_revoke))
        .route("/merchants/{merchant_id}/keys/{key_id}/rotate", post(key_rotate))
        .route("/checkouts", get(checkouts))
        .route("/checkouts/{checkout_id}", get(checkout_detail))
        .route("/webhooks", get(webhooks))
        .route("/webhooks/deliveries/{delivery_id}", get(delivery_detail))
        .route(
            "/webhooks/deliveries/{delivery_id}/retry",
            post(delivery_retry),
        )
        .route("/users", get(users_page).post(user_create))
        .route("/users/{user_id}/status", post(user_status))
        .route("/audit", get(audit_page))
        .layer(middleware::from_fn_with_state(state.clone(), require_admin));

    Router::new()
        .route("/login", get(login_page).post(login_submit))
        // Logout is public on purpose: it only clears the cookie, and both
        // admin and portal headers post here (a gated route would bounce
        // merchant users back to /portal without ever signing them out).
        .route("/logout", post(logout))
        .merge(protected)
}

/// `/portal`: the merchant-user surface — the full ops toolkit, scoped to the
/// signed-in user's own merchant (dashboard, checkouts, webhooks, keys, credits).
pub fn portal_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(portal_home))
        .route("/checkouts", get(portal_checkouts))
        .route("/checkouts/{checkout_id}", get(portal_checkout_detail))
        .route("/payment-links", post(portal_payment_link_create))
        .route("/webhooks", get(portal_webhooks))
        .route("/webhooks/endpoints", post(portal_webhook_create))
        .route("/webhooks/endpoints/{endpoint_id}/status", post(portal_webhook_status))
        .route("/webhooks/endpoints/{endpoint_id}/secret", post(portal_webhook_secret))
        .route("/webhooks/deliveries/{delivery_id}", get(portal_delivery_detail))
        .route(
            "/webhooks/deliveries/{delivery_id}/retry",
            post(portal_delivery_retry),
        )
        .route("/keys", get(portal_keys_page))
        .route("/keys/generate", post(portal_key_generate))
        .route("/keys/{key_id}/revoke", post(portal_key_revoke))
        .route("/keys/{key_id}/rotate", post(portal_key_rotate))
        .route("/methods", get(portal_methods_page).post(portal_method_create))
        .route("/methods/{method_id}/status", post(portal_method_status))
        .route("/methods/{method_id}/account", post(portal_method_account))
        .route("/methods/{method_id}/name", post(portal_method_name))
        .route("/credits", get(portal_credits_page))
        .route("/credits/buy", post(credits_buy))
        .layer(middleware::from_fn_with_state(state, require_merchant))
}

// ---------------------------------------------------------------------------
// Login / logout / signup
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_login.html")]
pub struct LoginPage {
    pub error: bool,
    /// Set after /signup: "account created, sign in to see approval status".
    pub created: bool,
}

pub async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(session) = session_info(&state, &headers).await {
        let next = if session.user.role == "merchant" { "/portal" } else { "/admin" };
        return Redirect::to(next).into_response();
    }
    page(
        StatusCode::OK,
        LoginPage {
            error: false,
            created: params.get("created").map(String::as_str) == Some("1"),
        },
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(&headers);
    let email = form.email.trim().to_lowercase();
    let row: Option<(String, String, String, String)> = db::query_as(
        "SELECT id, password_hash, role, email FROM users \
         WHERE lower(email) = ? AND status = 'active'",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some((user_id, password_hash, role, user_email)) = row else {
        audit(&state.pool, &email, ip.as_deref(), "user.login_failed", "user", &email, None).await;
        return (
            StatusCode::UNAUTHORIZED,
            Html(
                LoginPage { error: true, created: false }
                    .render()
                    .unwrap_or_else(|_| "login failed".into()),
            ),
        )
            .into_response();
    };
    if !verify_password(&form.password, &password_hash) {
        audit(&state.pool, &email, ip.as_deref(), "user.login_failed", "user", &email, None).await;
        return (
            StatusCode::UNAUTHORIZED,
            Html(
                LoginPage { error: true, created: false }
                    .render()
                    .unwrap_or_else(|_| "login failed".into()),
            ),
        )
            .into_response();
    }

    let next = if role == "merchant" { "/portal" } else { "/admin" };
    let cookie = format!(
        "{USER_COOKIE}={user_id}.{}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200",
        session_token(&password_hash, &user_id)
    );
    audit(&state.pool, &user_email, ip.as_deref(), "user.login", "user", &user_id, None).await;
    (
        StatusCode::SEE_OTHER,
        [("set-cookie", cookie), ("location", next.to_string())],
    )
        .into_response()
}

pub async fn logout() -> Response {
    let cookie = format!("{USER_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    (
        StatusCode::SEE_OTHER,
        [("set-cookie", cookie), ("location", "/admin/login".to_string())],
    )
        .into_response()
}

// --- merchant signup ---------------------------------------------------------

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupPage {
    pub error: Option<String>,
}

pub async fn signup_page() -> Response {
    page(StatusCode::OK, SignupPage { error: None })
}

#[derive(Deserialize)]
pub struct SignupForm {
    pub merchant_name: String,
    pub name: String,
    pub email: String,
    pub password: String,
}

/// Merchant self-signup: creates a `pending` merchant plus its owner user
/// (role `merchant`). A superadmin approves the merchant; until then the
/// merchant fails API-key authentication.
pub async fn signup_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Response {
    let merchant_name = form.merchant_name.trim().to_string();
    let name = form.name.trim().to_string();
    let email = form.email.trim().to_lowercase();
    let password = form.password.trim().to_string();

    let error = |msg: &str| {
        page(
            StatusCode::BAD_REQUEST,
            SignupPage { error: Some(msg.to_string()) },
        )
    };
    if merchant_name.is_empty() {
        return error("Business name is required.");
    }
    if !email.contains('@') || email.len() < 5 {
        return error("Enter a valid email address.");
    }
    if password.len() < 8 {
        return error("Password must be at least 8 characters.");
    }
    let (exists,): (i64,) = match db::query_as(
        "SELECT COUNT(*) FROM users WHERE lower(email) = ?",
    )
    .bind(&email)
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(e) => return db_error(e),
    };
    if exists > 0 {
        return error("This email is already registered — sign in instead.");
    }

    let merchant_id = new_id("mch");
    let user_id = new_id("usr");
    let mut db = match state.pool.begin().await {
        Ok(db) => db,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db::query(
        "INSERT INTO merchants (id, name, status, onboarding_status, created_at) \
         VALUES (?, ?, 'active', 'pending', ?)",
    )
    .bind(&merchant_id)
    .bind(&merchant_name)
    .bind(now_iso())
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    if let Err(e) = db::query(
        "INSERT INTO users (id, email, name, password_hash, role, merchant_id, status, created_at) \
         VALUES (?, ?, ?, ?, 'merchant', ?, 'active', ?)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&name)
    .bind(hash_password(&password))
    .bind(&merchant_id)
    .bind(now_iso())
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    if let Err(e) = db.commit().await {
        return db_error(e);
    }

    audit(
        &state.pool,
        &email,
        client_ip(&headers).as_deref(),
        "merchant.signup",
        "merchant",
        &merchant_id,
        Some(format!("{{\"user\":\"{user_id}\"}}")),
    )
    .await;

    Redirect::to("/admin/login?created=1").into_response()
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

pub struct RecentPayment {
    pub checkout_id: String,
    pub reference: String,
    pub merchant: String,
    pub amount_display: String,
    pub status: String,
}

#[derive(askama::Template)]
#[template(path = "admin_dashboard.html")]
pub struct DashboardPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub today_total: i64,
    pub today_succeeded: i64,
    pub today_failed: i64,
    pub volume_display: String,
    pub pending: i64,
    pub recent: Vec<RecentPayment>,
    pub activity: Vec<ActivityDay>,
}

pub async fn dashboard(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    // ISO timestamps sort lexicographically, so ">= YYYY-MM-DD" is "today UTC".
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let by_status: Vec<(String, i64, i64)> = match db::query_as(
        "SELECT status, COUNT(*), CAST(COALESCE(SUM(amount_minor), 0) AS BIGINT) \
         FROM checkouts WHERE created_at >= ? GROUP BY status",
    )
    .bind(&today)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => return db_error(e),
    };

    let mut today_total = 0i64;
    let mut today_succeeded = 0i64;
    let mut today_failed = 0i64;
    let mut volume_minor = 0i64;
    for (status, count, sum) in by_status {
        today_total += count;
        match status.as_str() {
            "succeeded" => {
                today_succeeded = count;
                volume_minor = sum;
            }
            "failed" => today_failed = count,
            _ => {}
        }
    }

    let (pending,): (i64,) = match db::query_as(
        "SELECT COUNT(*) FROM checkouts WHERE status = 'pending'",
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(e) => return db_error(e),
    };

    let recent = match db::query_as::<
        (String, String, i64, String, String, String),
    >(
        "SELECT c.id, c.reference, c.amount_minor, c.currency, c.status, m.name \
         FROM checkouts c JOIN merchants m ON m.id = c.merchant_id \
         ORDER BY c.created_at DESC LIMIT 10",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(id, reference, amount_minor, currency, status, merchant)| RecentPayment {
                checkout_id: id,
                amount_display: format!("{} {currency}", format_minor(amount_minor)),
                reference,
                merchant,
                status,
            })
            .collect(),
        Err(e) => return db_error(e),
    };

    // 14-day payment activity for the chart (zero days included).
    let start_day = (chrono::Utc::now() - chrono::Duration::days(13))
        .format("%Y-%m-%d")
        .to_string();
    let per_day: Vec<(String, i64, i64)> = db::query_as(
        "SELECT substr(created_at, 1, 10) AS day, COUNT(*), CAST(COALESCE(SUM(amount_minor), 0) AS BIGINT) FROM checkouts WHERE created_at >= ? GROUP BY day ORDER BY day",
    )
    .bind(&start_day)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let max_count = per_day.iter().map(|(_, c, _)| *c).max().unwrap_or(0);
    let mut activity = Vec::new();
    for i in 0..14 {
        let date = chrono::Utc::now() - chrono::Duration::days((13 - i) as i64);
        let key = date.format("%Y-%m-%d").to_string();
        let (count, sum) = per_day
            .iter()
            .find(|(d, _, _)| *d == key)
            .map(|(_, c, s)| (*c, *s))
            .unwrap_or((0, 0));
        let height_pct = if max_count > 0 && count > 0 { ((count * 100) / max_count) as u32 } else { 0 };
        activity.push(ActivityDay {
            day: date.format("%b %d").to_string(),
            count,
            volume_display: format_minor(sum),
            height_pct,
        });
    }
    page(
        StatusCode::OK,
        DashboardPage {
            section: "dashboard",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            today_total,
            today_succeeded,
            today_failed,
            volume_display: format_minor(volume_minor),
            pending,
            recent,
            activity,
        },
    )
}

// ---------------------------------------------------------------------------
// Merchants
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_merchants.html")]
pub struct MerchantsPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub rows: Vec<MerchantRow>,
}

pub struct MerchantRow {
    pub id: String,
    pub name: String,
    pub status: String,
    pub onboarding: String,
    pub checkout_count: i64,
}

pub async fn merchants(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    let rows = match db::query_as::<(String, String, String, String, i64)>(
        "SELECT m.id, m.name, m.status, m.onboarding_status, COUNT(c.id) \
         FROM merchants m LEFT JOIN checkouts c ON c.merchant_id = m.id \
         GROUP BY m.id, m.name, m.status, m.onboarding_status ORDER BY m.created_at",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(id, name, status, onboarding, checkout_count)| MerchantRow {
                id,
                name,
                status,
                onboarding,
                checkout_count,
            })
            .collect(),
        Err(e) => return db_error(e),
    };
    page(
        StatusCode::OK,
        MerchantsPage { section: "merchants", csrf: sess.token.clone(), email: sess.user.email.clone(), rows },
    )
}

pub struct MerchantMethodRow {
    pub method_id: String,
    pub provider: String,
    pub display_name: String,
    pub account_identifier: String,
    pub instructions: String,
    pub status: String,
}

pub struct MerchantKeyRow {
    pub key_id: String,
    pub prefix: String,
    pub created_at: String,
    pub active: bool,
}

pub struct MerchantEndpointRow {
    pub url: String,
    pub status: String,
}

pub struct MerchantCheckoutRow {
    pub checkout_id: String,
    pub reference: String,
    pub amount_display: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "admin_merchant.html")]
pub struct MerchantPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_id: String,
    pub name: String,
    pub status: String,
    pub onboarding: String,
    pub credits: i64,
    pub created_at: String,
    pub methods: Vec<MerchantMethodRow>,
    pub keys: Vec<MerchantKeyRow>,
    pub endpoints: Vec<MerchantEndpointRow>,
    pub checkouts: Vec<MerchantCheckoutRow>,
    /// A freshly created API key, rendered exactly once (create/rotate).
    pub new_key: Option<String>,
    /// Selectable providers for the add-method form.
    pub providers: Vec<(String, String)>,
}

pub async fn merchant_detail(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Path(merchant_id): Path<String>,
) -> Response {
    merchant_page(&state, &merchant_id, None, sess.token.clone(), sess.user.email.clone()).await
}

async fn merchant_page(
    state: &AppState,
    merchant_id: &str,
    new_key: Option<String>,
    csrf: String,
    email: String,
) -> Response {
    let Some((name, status, onboarding, credits, created_at)) = db::query_as::<
        (String, String, String, i64, String),
    >(
        "SELECT name, status, onboarding_status, credit_balance, created_at FROM merchants WHERE id = ?",
    )
    .bind(merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };

    let methods = match db::query_as::<(String, String, String, String, String, String)>(
        "SELECT id, provider, display_name, account_identifier, instructions, status \
         FROM merchant_payment_methods WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(method_id, provider, display_name, account_identifier, instructions, status)| {
                    MerchantMethodRow {
                        method_id,
                        provider,
                        display_name,
                        account_identifier,
                        instructions,
                        status,
                    }
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let keys = match db::query_as::<(String, String, String, Option<String>)>(
        "SELECT id, prefix, created_at, revoked_at FROM merchant_api_keys \
         WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(key_id, prefix, created_at, revoked_at)| MerchantKeyRow {
                key_id,
                prefix,
                created_at,
                active: revoked_at.is_none(),
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let endpoints = match db::query_as::<(String, String)>(
        "SELECT url, status FROM webhook_endpoints WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(url, status)| MerchantEndpointRow { url, status })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let checkouts = match db::query_as::<(String, String, i64, String, String)>(
        "SELECT id, reference, amount_minor, status, created_at FROM checkouts \
         WHERE merchant_id = ? ORDER BY created_at DESC LIMIT 10",
    )
    .bind(merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, reference, amount_minor, status, created_at)| MerchantCheckoutRow {
                checkout_id: id,
                reference,
                amount_display: format_minor(amount_minor),
                status,
                created_at,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        MerchantPage {
            section: "merchants",
            csrf,
            email,
            merchant_id: merchant_id.to_string(),
            name,
            status,
            onboarding,
            credits,
            created_at,
            methods,
            keys,
            endpoints,
            checkouts,
            new_key,
            providers: PROVIDERS
                .iter()
                .map(|(p, n)| (p.to_string(), n.to_string()))
                .collect(),
        },
    )
}

#[derive(Deserialize)]
pub struct MerchantStatusForm {
    pub csrf: String,
    pub action: String,
}

/// Suspend (disable) or reactivate a merchant. Suspended merchants fail API
/// key authentication immediately (`m.status = 'active'` in auth.rs).
pub async fn merchant_status(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
    Form(form): Form<MerchantStatusForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let next_status = match form.action.as_str() {
        "suspend" => "disabled",
        "reactivate" => "active",
        _ => return bad_request("unknown action"),
    };

    if let Err(e) = db::query("UPDATE merchants SET status = ? WHERE id = ?")
        .bind(next_status)
        .bind(&merchant_id)
        .execute(&state.pool)
        .await
    {
        return db_error(e);
    }

    let action = if next_status == "disabled" { "merchant.suspended" } else { "merchant.reactivated" };
    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        action,
        "merchant",
        &merchant_id,
        Some(format!("{{\"status\":\"{next_status}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

#[derive(Deserialize)]
pub struct ApproveForm {
    pub csrf: String,
}

/// Approve a signed-up merchant (pending -> approved). Until approval the
/// merchant's API keys fail authentication.
pub async fn merchant_approve(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
    Form(form): Form<ApproveForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }

    if let Err(e) = db::query(
        "UPDATE merchants SET onboarding_status = 'approved' \
         WHERE id = ? AND onboarding_status = 'pending'",
    )
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "merchant.approved",
        "merchant",
        &merchant_id,
        None,
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

#[derive(Deserialize)]
pub struct CreditsGrantForm {
    pub csrf: String,
    /// Whole ETB; 1 ETB = 1 credit.
    pub amount: i64,
}

/// Manually grant credit (support path: the merchant paid out of band).
/// The balance move is written to the credit ledger and audited.
pub async fn credits_grant(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
    Form(form): Form<CreditsGrantForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    if form.amount <= 0 || form.amount > 1_000_000 {
        return bad_request("credit amount must be between 1 and 1,000,000");
    }

    let mut db = match state.pool.begin().await {
        Ok(db) => db,
        Err(e) => return db_error(e),
    };
    let updated = match db::query(
        "UPDATE merchants SET credit_balance = credit_balance + ? WHERE id = ?",
    )
    .bind(form.amount)
    .bind(&merchant_id)
    .execute(&mut *db)
    .await
    {
        Ok(r) => r,
        Err(e) => return db_error(e),
    };
    if updated.rows_affected() == 0 {
        return bad_request("merchant not found");
    }
    if let Err(e) = db::query(
        "INSERT INTO credit_ledger (id, merchant_id, delta, reason, checkout_id, created_at) \
         VALUES (?, ?, ?, 'admin_grant', NULL, ?)",
    )
    .bind(new_id("crl"))
    .bind(&merchant_id)
    .bind(form.amount)
    .bind(now_iso())
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    if let Err(e) = db.commit().await {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "credits.granted",
        "merchant",
        &merchant_id,
        Some(format!("{{\"credits\":{}}}", form.amount)),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

// ---------------------------------------------------------------------------
// Merchant payment methods
// ---------------------------------------------------------------------------

const PROVIDERS: [(&str, &str); 7] = [
    ("telebirr", "Telebirr"),
    ("cbe", "CBE Birr"),
    ("boa", "Bank of Abyssinia"),
    ("zemen", "Zemen Bank"),
    ("dashen", "Dashen Bank"),
    ("awash", "Awash"),
    ("mpesa", "M-Pesa"),
];

const DEFAULT_INSTRUCTIONS: &str = "Send exactly the checkout amount to the account shown\n\
    Copy the transaction reference from your wallet app\n\
    Return to this page and paste the reference";

/// Customer instructions come from central per-provider config (migration
/// 0006, editable by admins) — merchants never write the steps themselves.
async fn provider_default_instructions(pool: &Pool, provider: &str) -> String {
    db::query_as::<(String,)>(
        "SELECT instructions FROM provider_instructions WHERE provider = ?",
    )
    .bind(provider)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(i,)| i)
    .unwrap_or_else(|| DEFAULT_INSTRUCTIONS.to_string())
}

#[derive(Deserialize)]
pub struct MethodCreateForm {
    pub csrf: String,
    pub provider: String,
    pub display_name: Option<String>,
    pub account_identifier: String,
    pub instructions: Option<String>,
}

/// Add a receiving account for the merchant. The account identifier is the
/// exact-match target of the verification chain (recipient_mismatch), so it
/// lives in platform configuration — never supplied per checkout.
pub async fn method_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
    Form(form): Form<MethodCreateForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((_, default_name)) = PROVIDERS.iter().find(|(p, _)| *p == form.provider.as_str())
    else {
        return bad_request("unknown provider");
    };
    let account = form.account_identifier.trim().to_string();
    if account.is_empty() {
        return bad_request("receiving account is required");
    }
    let display_name = form
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_name)
        .to_string();
    let instructions = match form.instructions.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(custom) => custom.to_string(),
        None => provider_default_instructions(&state.pool, &form.provider).await,
    };

    if let Err(e) = db::query(
        "INSERT INTO merchant_payment_methods \
         (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("mpm"))
    .bind(&merchant_id)
    .bind(&form.provider)
    .bind(&display_name)
    .bind(&account)
    .bind(&instructions)
    .bind(now_iso())
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.added",
        "merchant",
        &merchant_id,
        Some(format!("{{\"provider\":\"{}\",\"account\":\"{account}\"}}", form.provider)),
    )
    .await;

    merchant_page(&state, &merchant_id, None, sess.token.clone(), sess.user.email.clone()).await
}

#[derive(Deserialize)]
pub struct MethodStatusForm {
    pub csrf: String,
    pub action: String,
}

/// Enable/disable a payment method. Disabled methods disappear from the
/// merchant's hosted checkout and cannot be newly selected.
pub async fn method_status(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, method_id)): Path<(String, String)>,
    Form(form): Form<MethodStatusForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let next_status = match form.action.as_str() {
        "enable" => "active",
        "disable" => "disabled",
        _ => return bad_request("unknown action"),
    };

    if let Err(e) = db::query(
        "UPDATE merchant_payment_methods SET status = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(next_status)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    let action = if next_status == "active" { "payment_method.enabled" } else { "payment_method.disabled" };
    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        action,
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"status\":\"{next_status}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

#[derive(Deserialize)]
pub struct MethodAccountForm {
    pub csrf: String,
    pub account_identifier: String,
}

/// Change the receiving wallet. Audited with the new value; the transactions
/// table keeps the recipient that was matched at each payment's time.
pub async fn method_account(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, method_id)): Path<(String, String)>,
    Form(form): Form<MethodAccountForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let account = form.account_identifier.trim().to_string();
    if account.is_empty() {
        return bad_request("receiving account is required");
    }

    if let Err(e) = db::query(
        "UPDATE merchant_payment_methods SET account_identifier = ? \
         WHERE id = ? AND merchant_id = ?",
    )
    .bind(&account)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.account_changed",
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"account\":\"{account}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

#[derive(Deserialize)]
pub struct MethodInstructionsForm {
    pub csrf: String,
    pub instructions: String,
}

#[derive(Deserialize)]
pub struct MethodNameForm {
    pub csrf: String,
    pub display_name: String,
}

/// Rename a payment method — the display name shown to customers on the
/// checkout (never the provider name unless the merchant chooses it).
pub async fn method_name(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, method_id)): Path<(String, String)>,
    Form(form): Form<MethodNameForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let name = form.display_name.trim().to_string();
    if name.is_empty() || name.len() > 60 {
        return bad_request("display name must be 1-60 characters");
    }

    if let Err(e) = db::query(
        "UPDATE merchant_payment_methods SET display_name = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(&name)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.renamed",
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"name\":\"{name}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

/// Edit the customer-facing steps of a method (central config; merchants see
/// them but never write them).
pub async fn method_instructions(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, method_id)): Path<(String, String)>,
    Form(form): Form<MethodInstructionsForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageMerchants) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let steps = form.instructions.trim().to_string();
    if steps.is_empty() {
        return bad_request("instructions must not be empty");
    }

    if let Err(e) = db::query(
        "UPDATE merchant_payment_methods SET instructions = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(&steps)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.instructions_changed",
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

// ---------------------------------------------------------------------------
// Merchant API keys
// ---------------------------------------------------------------------------

/// 160 bits of OS randomness via two ULIDs, on top of the `pb_sk_{kind}_`
/// prefix so the kind stays visible in the stored lookup prefix.
fn generate_api_key(kind: &str) -> String {
    format!("pb_sk_{kind}_{}{}", ulid::Ulid::new(), ulid::Ulid::new())
}

async fn insert_api_key(
    pool: &Pool,
    merchant_id: &str,
    kind: &str,
) -> Result<String, sqlx::Error> {
    let secret = generate_api_key(kind);
    db::query(
        "INSERT INTO merchant_api_keys (id, merchant_id, prefix, key_hash, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(new_id("key"))
    .bind(merchant_id)
    .bind(&secret[..12])
    .bind(crate::auth::sha256_hex(&secret))
    .bind(now_iso())
    .execute(pool)
    .await?;
    Ok(secret)
}

#[derive(Deserialize)]
pub struct KeyCreateForm {
    pub csrf: String,
    pub kind: String,
}

/// Create an API key. The full secret is rendered once on the resulting page
/// (stored only as a SHA-256 hash + 12-char lookup prefix) and never again.
pub async fn key_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
    Form(form): Form<KeyCreateForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageApiKeys) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    if !matches!(form.kind.as_str(), "test" | "live") {
        return bad_request("kind must be test or live");
    }

    let secret = match insert_api_key(&state.pool, &merchant_id, &form.kind).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.created",
        "merchant",
        &merchant_id,
        Some(format!("{{\"kind\":\"{}\",\"prefix\":\"{}\"}}", form.kind, &secret[..12])),
    )
    .await;

    merchant_page(&state, &merchant_id, Some(secret), sess.token.clone(), sess.user.email.clone()).await
}

#[derive(Deserialize)]
pub struct KeyActionForm {
    pub csrf: String,
}

/// Revoke a key: it stops authenticating immediately (revoked_at filter in
/// auth.rs). The key row and audit trail remain for history.
pub async fn key_revoke(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, key_id)): Path<(String, String)>,
    Form(form): Form<KeyActionForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageApiKeys) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }

    let prefix: Option<(String,)> = db::query_as(
        "SELECT prefix FROM merchant_api_keys WHERE id = ? AND merchant_id = ?",
    )
    .bind(&key_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((prefix,)) = prefix else {
        return not_found();
    };

    if let Err(e) = db::query(
        "UPDATE merchant_api_keys SET revoked_at = ? \
         WHERE id = ? AND merchant_id = ? AND revoked_at IS NULL",
    )
    .bind(now_iso())
    .bind(&key_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.revoked",
        "merchant",
        &merchant_id,
        Some(format!("{{\"key\":\"{key_id}\",\"prefix\":\"{prefix}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/merchants/{merchant_id}")).into_response()
}

/// Rotate a key: revoke the old one and create a replacement in one action.
/// The new secret is shown once; the old key dies immediately.
pub async fn key_rotate(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path((merchant_id, key_id)): Path<(String, String)>,
    Form(form): Form<KeyActionForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageApiKeys) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }

    let old: Option<(String, String)> = db::query_as(
        "SELECT prefix, created_at FROM merchant_api_keys WHERE id = ? AND merchant_id = ?",
    )
    .bind(&key_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((old_prefix, old_created)) = old else {
        return not_found();
    };
    // Preserve the kind (test/live) of the key being rotated.
    let kind = old_prefix
        .strip_prefix("pb_sk_")
        .and_then(|rest| rest.split('_').next())
        .unwrap_or("test")
        .to_string();

    let mut db = match state.pool.begin().await {
        Ok(db) => db,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db::query(
        "UPDATE merchant_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now_iso())
    .bind(&key_id)
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    let new_secret = match insert_api_key_tx(&mut db, &merchant_id, &kind).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db.commit().await {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.rotated",
        "merchant",
        &merchant_id,
        Some(format!(
            "{{\"key\":\"{key_id}\",\"old_prefix\":\"{old_prefix}\",\"new_prefix\":\"{}\",\"created\":\"{old_created}\"}}",
            &new_secret[..12]
        )),
    )
    .await;

    merchant_page(&state, &merchant_id, Some(new_secret), sess.token.clone(), sess.user.email.clone()).await
}

/// Same as `insert_api_key` but on an open transaction (used by rotate).
async fn insert_api_key_tx(
    db: &mut <Db as sqlx::Database>::Connection,
    merchant_id: &str,
    kind: &str,
) -> Result<String, sqlx::Error> {
    let secret = generate_api_key(kind);
    db::query(
        "INSERT INTO merchant_api_keys (id, merchant_id, prefix, key_hash, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(new_id("key"))
    .bind(merchant_id)
    .bind(&secret[..12])
    .bind(crate::auth::sha256_hex(&secret))
    .bind(now_iso())
    .execute(db)
    .await?;
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Checkouts
// ---------------------------------------------------------------------------

pub struct CheckoutRow {
    pub checkout_id: String,
    pub reference: String,
    pub merchant: String,
    pub amount_display: String,
    pub method: String,
    pub transaction_reference: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(askama::Template)]
#[template(path = "admin_checkouts.html")]
pub struct CheckoutsPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub rows: Vec<CheckoutRow>,
    pub merchants: Vec<(String, String)>,
    pub q: String,
    pub status: String,
    pub merchant: String,
}

#[derive(Deserialize)]
pub struct CheckoutFilters {
    pub q: Option<String>,
    pub status: Option<String>,
    pub merchant: Option<String>,
}

pub async fn checkouts(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Query(f): Query<CheckoutFilters>,
) -> Response {
    let merchants = match db::query_as::<(String, String)>(
        "SELECT id, name FROM merchants ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let q = f.q.unwrap_or_default().trim().to_string();
    let status = f.status.unwrap_or_default();
    let merchant = f.merchant.unwrap_or_default();

    let mut qb = db::query_builder(
        "SELECT c.id, c.reference, c.amount_minor, c.status, c.created_at, m.name, \
                COALESCE(pm.display_name, ''), \
                (SELECT t.transaction_reference FROM transactions t \
                 JOIN payments p ON p.id = t.payment_id \
                 WHERE p.checkout_id = c.id AND p.status = 'succeeded' \
                 ORDER BY t.created_at DESC LIMIT 1) \
         FROM checkouts c \
         JOIN merchants m ON m.id = c.merchant_id \
         LEFT JOIN merchant_payment_methods pm ON pm.id = c.selected_method_id \
         WHERE 1=1",
    );
    if matches!(status.as_str(), "created" | "pending" | "succeeded" | "failed" | "expired") {
        qb.push(" AND c.status = ").push_bind(status.clone());
    }
    if !merchant.is_empty() {
        qb.push(" AND c.merchant_id = ").push_bind(merchant.clone());
    }
    if !q.is_empty() {
        let needle = format!("%{q}%");
        qb.push(" AND (c.reference LIKE ")
            .push_bind(needle.clone())
            .push(" OR c.id LIKE ")
            .push_bind(needle.clone())
            .push(" OR EXISTS (SELECT 1 FROM payments p JOIN transactions t ON t.payment_id = p.id \
                   WHERE p.checkout_id = c.id AND t.transaction_reference LIKE ")
            .push_bind(needle)
            .push("))");
    }
    qb.push(" ORDER BY c.created_at DESC LIMIT 50");

    let rows = match qb
        .build_query_as::<(String, String, i64, String, String, String, String, Option<String>)>()
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(
                |(id, reference, amount_minor, status, created_at, merchant, method, txn_ref)| {
                    CheckoutRow {
                        checkout_id: id,
                        reference,
                        amount_display: format_minor(amount_minor),
                        status,
                        created_at,
                        merchant,
                        method,
                        transaction_reference: txn_ref,
                    }
                },
            )
            .collect(),
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        CheckoutsPage {
            section: "checkouts",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            rows,
            merchants,
            q,
            status,
            merchant,
        },
    )
}

pub struct AttemptRow {
    pub outcome: String,
    pub detail: Option<String>,
    pub transaction_reference: String,
    pub created_at: String,
}

/// One step of the payment story shown on checkout detail pages:
/// created -> payment submitted -> verified -> webhook delivered.
pub struct TimelineRow {
    pub label: String,
    pub at: String,
}

/// One day of the 14-day payment activity chart.
pub struct ActivityDay {
    pub day: String,
    pub count: i64,
    pub volume_display: String,
    pub height_pct: u32,
}

async fn checkout_timeline(
    pool: &Pool,
    checkout_id: &str,
    created_at: &str,
    paid_at: &Option<String>,
) -> Vec<TimelineRow> {
    let mut rows = vec![TimelineRow {
        label: "Checkout created".to_string(),
        at: created_at.to_string(),
    }];
    if let Ok(Some((submitted,))) = db::query_as::<(String,)>(
        "SELECT MIN(created_at) FROM payments WHERE checkout_id = ?",
    )
    .bind(checkout_id)
    .fetch_optional(pool)
    .await
    {
        rows.push(TimelineRow { label: "Payment submitted".to_string(), at: submitted });
    }
    if let Some(paid) = paid_at {
        rows.push(TimelineRow { label: "Transaction verified".to_string(), at: paid.clone() });
    }
    if let Ok(Some((delivered,))) = db::query_as::<(String,)>(
        "SELECT MIN(d.created_at) FROM webhook_deliveries d JOIN outbox_messages o ON o.id = d.outbox_id WHERE o.aggregate_id = ? AND d.status_code BETWEEN 200 AND 299",
    )
    .bind(checkout_id)
    .fetch_optional(pool)
    .await
    {
        rows.push(TimelineRow { label: "Webhook delivered".to_string(), at: delivered });
    }
    rows
}

pub struct DeliveryRow {
    pub delivery_id: String,
    pub attempt_no: i64,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub created_at: String,
}

pub struct EventRow {
    pub event_id: String,
    pub event_type: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
    pub payload: String,
    pub deliveries: Vec<DeliveryRow>,
}

pub struct TransactionView {
    pub reference: String,
    pub amount_display: String,
    pub currency: String,
    pub recipient: String,
    pub occurred_at: String,
}

#[derive(askama::Template)]
#[template(path = "admin_checkout.html")]
pub struct CheckoutPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub checkout_id: String,
    pub reference: String,
    pub merchant_id: String,
    pub merchant: String,
    pub amount_display: String,
    pub currency: String,
    pub status: String,
    pub customer: String,
    pub return_url: Option<String>,
    pub method: Option<(String, String)>,
    pub transaction: Option<TransactionView>,
    pub created_at: String,
    pub paid_at: Option<String>,
    pub expires_at: String,
    pub attempts: Vec<AttemptRow>,
    pub events: Vec<EventRow>,
    pub timeline: Vec<TimelineRow>,
}

pub async fn checkout_detail(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Path(checkout_id): Path<String>,
) -> Response {
    let Some((
        reference,
        amount_minor,
        currency,
        status,
        customer_name,
        customer_email,
        return_url,
        expires_at,
        created_at,
        paid_at,
        selected_method_id,
        merchant,
        merchant_id,
    )) = db::query_as::<
        (
            String,
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
        ),
    >(
        "SELECT c.reference, c.amount_minor, c.currency, c.status, c.customer_name, c.customer_email, \
                c.return_url, c.expires_at, c.created_at, c.paid_at, c.selected_method_id, \
                m.name, m.id \
         FROM checkouts c JOIN merchants m ON m.id = c.merchant_id WHERE c.id = ?",
    )
    .bind(&checkout_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };

    let method = match &selected_method_id {
        Some(method_id) => db::query_as::<(String, String)>(
            "SELECT provider, display_name FROM merchant_payment_methods WHERE id = ?",
        )
        .bind(method_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten(),
        None => None,
    };

    let transaction = db::query_as::<(String, i64, String, String, String)>(
        "SELECT t.transaction_reference, t.amount_minor, t.currency, t.recipient, t.occurred_at \
         FROM transactions t JOIN payments p ON p.id = t.payment_id \
         WHERE p.checkout_id = ? AND p.status = 'succeeded' \
         ORDER BY t.created_at DESC LIMIT 1",
    )
    .bind(&checkout_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|(reference, amount_minor, txn_currency, recipient, occurred_at)| TransactionView {
        reference,
        amount_display: format_minor(amount_minor),
        currency: txn_currency,
        recipient,
        occurred_at,
    });

    let attempts = match db::query_as::<(String, Option<String>, String, String)>(
        "SELECT outcome, detail, transaction_reference, created_at FROM payment_attempts \
         WHERE checkout_id = ? ORDER BY created_at DESC LIMIT 20",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(outcome, detail, transaction_reference, created_at)| AttemptRow {
                outcome,
                detail,
                transaction_reference,
                created_at,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let mut events: Vec<EventRow> = db::query_as::<
        (String, String, String, i64, String, Option<String>, String),
    >(
        "SELECT id, event_type, status, attempts, next_attempt_at, last_error, payload \
         FROM outbox_messages WHERE aggregate_id = ? ORDER BY created_at DESC",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, event_type, ev_status, ev_attempts, next_attempt_at, last_error, payload)| {
                EventRow {
                    event_id: id.clone(),
                    event_type,
                    status: ev_status,
                    attempts: ev_attempts,
                    next_attempt_at,
                    last_error,
                    payload,
                    deliveries: Vec::new(),
                }
            })
            .collect()
    })
    .unwrap_or_default();

    // All delivery attempts for this checkout's events, grouped per event.
    let all_deliveries = match db::query_as::<
        (String, String, i64, Option<i64>, Option<String>, Option<i64>, String),
    >(
        "SELECT d.outbox_id, d.id, d.attempt_no, d.status_code, d.error, d.duration_ms, d.created_at \
         FROM webhook_deliveries d JOIN outbox_messages o ON o.id = d.outbox_id \
         WHERE o.aggregate_id = ? ORDER BY d.attempt_no",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    for (outbox_id, delivery_id, attempt_no, status_code, error, duration_ms, created_at) in
        all_deliveries
    {
        if let Some(event) = events.iter_mut().find(|e| e.event_id == outbox_id) {
            event.deliveries.push(DeliveryRow {
                delivery_id,
                attempt_no,
                status_code,
                error,
                duration_ms,
                created_at,
            });
        }
    }

    let customer = [customer_name, customer_email]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" \u{b7} ");

    let timeline = checkout_timeline(&state.pool, &checkout_id, &created_at, &paid_at).await;
    page(
        StatusCode::OK,
        CheckoutPage {
            section: "checkouts",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            checkout_id,
            reference,
            merchant_id,
            merchant,
            amount_display: format_minor(amount_minor),
            currency,
            status,
            customer,
            return_url,
            method,
            transaction,
            created_at,
            paid_at,
            expires_at,
            attempts,
            events,
            timeline,
        },
    )
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

pub struct EndpointRow {
    pub endpoint_id: String,
    pub merchant: String,
    pub url: String,
    pub status: String,
}

pub struct DeliveryListRow {
    pub delivery_id: String,
    pub event_id: String,
    pub event_type: String,
    pub merchant: String,
    pub attempt_no: i64,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub created_at: String,
}

#[derive(askama::Template)]
#[template(path = "admin_webhooks.html")]
pub struct WebhooksPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub endpoints: Vec<EndpointRow>,
    pub deliveries: Vec<DeliveryListRow>,
}

pub async fn webhooks(State(state): State<AppState>, Extension(sess): Extension<SessionInfo>) -> Response {
    let endpoints = match db::query_as::<(String, String, String, String)>(
        "SELECT e.id, m.name, e.url, e.status \
         FROM webhook_endpoints e JOIN merchants m ON m.id = e.merchant_id \
         ORDER BY m.name, e.created_at",
    )
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(endpoint_id, merchant, url, status)| EndpointRow {
                endpoint_id,
                merchant,
                url,
                status,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let deliveries = match db::query_as::<
        (String, String, String, String, i64, Option<i64>, Option<String>, String),
    >(
        "SELECT d.id, o.id, o.event_type, m.name, d.attempt_no, d.status_code, d.error, d.created_at \
         FROM webhook_deliveries d \
         JOIN outbox_messages o ON o.id = d.outbox_id \
         JOIN webhook_endpoints e ON e.id = d.endpoint_id \
         JOIN merchants m ON m.id = e.merchant_id \
         ORDER BY d.created_at DESC LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(delivery_id, event_id, event_type, merchant, attempt_no, status_code, error, created_at)| {
                    DeliveryListRow {
                        delivery_id,
                        event_id,
                        event_type,
                        merchant,
                        attempt_no,
                        status_code,
                        error,
                        created_at,
                    }
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        WebhooksPage {
            section: "webhooks",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            endpoints,
            deliveries,
        },
    )
}

#[derive(Template)]
#[template(path = "admin_delivery.html")]
pub struct DeliveryPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub delivery_id: String,
    pub event_id: String,
    pub event_type: String,
    pub merchant: String,
    pub url: String,
    pub attempt_no: i64,
    pub status_code: Option<i64>,
    /// 2xx response on this attempt (drives the status badge).
    pub ok: bool,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub created_at: String,
    pub event_status: String,
    pub event_attempts: i64,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
    pub payload: String,
    pub history: Vec<DeliveryRow>,
}

pub async fn delivery_detail(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Path(delivery_id): Path<String>,
) -> Response {
    let Some((outbox_id, endpoint_id, attempt_no, status_code, error, duration_ms, created_at)) =
        db::query_as::<
            (String, String, i64, Option<i64>, Option<String>, Option<i64>, String),
        >(
            "SELECT outbox_id, endpoint_id, attempt_no, status_code, error, duration_ms, created_at \
             FROM webhook_deliveries WHERE id = ?",
        )
        .bind(&delivery_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };

    let Some((event_type, event_status, event_attempts, next_attempt_at, last_error, payload)) =
        db::query_as::<(String, String, i64, String, Option<String>, String)>(
            "SELECT event_type, status, attempts, next_attempt_at, last_error, payload \
             FROM outbox_messages WHERE id = ?",
        )
        .bind(&outbox_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };

    let (merchant, url) = db::query_as::<(String, String)>(
        "SELECT m.name, e.url FROM webhook_endpoints e \
         JOIN merchants m ON m.id = e.merchant_id WHERE e.id = ?",
    )
    .bind(&endpoint_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| ("?".into(), "?".into()));

    let history = match db::query_as::<(String, i64, Option<i64>, Option<String>, Option<i64>, String)>(
        "SELECT id, attempt_no, status_code, error, duration_ms, created_at \
         FROM webhook_deliveries WHERE outbox_id = ? ORDER BY attempt_no",
    )
    .bind(&outbox_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(delivery_id, attempt_no, status_code, error, duration_ms, created_at)| DeliveryRow {
                    delivery_id,
                    attempt_no,
                    status_code,
                    error,
                    duration_ms,
                    created_at,
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        DeliveryPage {
            section: "webhooks",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            delivery_id,
            event_id: outbox_id,
            event_type,
            merchant,
            url,
            attempt_no,
            ok: status_code.map(|c| (200..300).contains(&c)).unwrap_or(false),
            status_code,
            error,
            duration_ms,
            created_at,
            event_status,
            event_attempts,
            next_attempt_at,
            last_error,
            payload,
            history,
        },
    )
}

#[derive(Deserialize)]
pub struct RetryForm {
    pub csrf: String,
}

/// Re-queue the delivery's event: the dispatcher delivers it on its next poll.
/// Merchants dedupe on `eventId`, so redelivering a delivered event is safe.
pub async fn delivery_retry(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(delivery_id): Path<String>,
    Form(form): Form<RetryForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageWebhooks) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }

    let Some((event_id,)): Option<(String,)> = db::query_as(
        "SELECT outbox_id FROM webhook_deliveries WHERE id = ?",
    )
    .bind(&delivery_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };

    // One fresh attempt from the retry schedule; `now` makes the dispatcher
    // pick it up on its next poll.
    if let Err(e) = db::query(
        "UPDATE outbox_messages \
         SET status = 'pending', attempts = CASE WHEN attempts - 1 > 0 THEN attempts - 1 ELSE 0 END, next_attempt_at = ? \
         WHERE id = ?",
    )
    .bind(now_iso())
    .bind(&event_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "webhook.retried",
        "webhook_event",
        &event_id,
        Some(format!("{{\"delivery\":\"{delivery_id}\"}}")),
    )
    .await;

    Redirect::to(&format!("/admin/webhooks/deliveries/{delivery_id}")).into_response()
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

pub struct AuditRow {
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub resource_id: String,
    pub ip: Option<String>,
    pub metadata: Option<String>,
    pub created_at: String,
}

#[derive(askama::Template)]
#[template(path = "admin_audit.html")]
pub struct AuditPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub rows: Vec<AuditRow>,
}

pub async fn audit_page(State(state): State<AppState>, Extension(sess): Extension<SessionInfo>) -> Response {
    let rows = match db::query_as::<
        (String, String, String, String, Option<String>, Option<String>, String),
    >(
        "SELECT actor, action, resource, resource_id, ip, metadata, created_at \
         FROM audit_logs ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(actor, action, resource, resource_id, ip, metadata, created_at)| AuditRow {
                    actor,
                    action,
                    resource,
                    resource_id,
                    ip,
                    metadata,
                    created_at,
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        AuditPage { section: "audit", csrf: sess.token.clone(), email: sess.user.email.clone(), rows },
    )
}

// ---------------------------------------------------------------------------
// User management (superadmin only)
// ---------------------------------------------------------------------------

pub struct UserRow {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub merchant: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
pub struct UsersPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub rows: Vec<UserRow>,
    pub merchants: Vec<(String, String)>,
}

pub async fn users_page(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageUsers) {
        return forbidden();
    }
    let rows = match db::query_as::<
        (String, String, String, String, Option<String>, String, String),
    >(
        "SELECT u.id, u.email, u.name, u.role, m.name, u.status, u.created_at \
         FROM users u LEFT JOIN merchants m ON m.id = u.merchant_id \
         ORDER BY u.created_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(user_id, email, name, role, merchant, status, created_at)| UserRow {
                    user_id,
                    email,
                    name,
                    role,
                    merchant,
                    status,
                    created_at,
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    let merchants = match db::query_as::<(String, String)>(
        "SELECT id, name FROM merchants ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        UsersPage { section: "users", csrf: sess.token.clone(), email: sess.user.email.clone(), rows, merchants },
    )
}

#[derive(Deserialize)]
pub struct UserCreateForm {
    pub csrf: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub password: String,
    pub merchant_id: String,
}

pub async fn user_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<UserCreateForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageUsers) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }

    let email = form.email.trim().to_lowercase();
    let name = form.name.trim().to_string();
    let password = form.password.trim().to_string();
    if !email.contains('@') || email.len() < 5 {
        return bad_request("valid email is required");
    }
    if password.len() < 8 {
        return bad_request("password must be at least 8 characters");
    }
    if !matches!(
        form.role.as_str(),
        "superadmin" | "operations" | "support" | "developer" | "merchant"
    ) {
        return bad_request("unknown role");
    }
    let merchant_id = if form.role == "merchant" {
        let id = form.merchant_id.trim().to_string();
        if id.is_empty() {
            return bad_request("merchant users must be assigned to a merchant");
        }
        Some(id)
    } else {
        None
    };

    let (exists,): (i64,) = match db::query_as(
        "SELECT COUNT(*) FROM users WHERE lower(email) = ?",
    )
    .bind(&email)
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(e) => return db_error(e),
    };
    if exists > 0 {
        return bad_request("email already registered");
    }

    if let Err(e) = db::query(
        "INSERT INTO users (id, email, name, password_hash, role, merchant_id, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("usr"))
    .bind(&email)
    .bind(&name)
    .bind(hash_password(&password))
    .bind(&form.role)
    .bind(&merchant_id)
    .bind(now_iso())
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "user.created",
        "user",
        &email,
        Some(format!("{{\"role\":\"{}\"}}", form.role)),
    )
    .await;

    Redirect::to("/admin/users").into_response()
}

#[derive(Deserialize)]
pub struct UserStatusForm {
    pub csrf: String,
    pub action: String,
}

pub async fn user_status(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<UserStatusForm>,
) -> Response {
    if !can(&sess.user.role, &Cap::ManageUsers) {
        return forbidden();
    }
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    if user_id == sess.user.id {
        return bad_request("you cannot disable your own account");
    }
    let next_status = match form.action.as_str() {
        "enable" => "active",
        "disable" => "disabled",
        _ => return bad_request("unknown action"),
    };

    if let Err(e) = db::query("UPDATE users SET status = ? WHERE id = ?")
        .bind(next_status)
        .bind(&user_id)
        .execute(&state.pool)
        .await
    {
        return db_error(e);
    }

    let action = if next_status == "active" { "user.enabled" } else { "user.disabled" };
    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        action,
        "user",
        &user_id,
        None,
    )
    .await;

    Redirect::to("/admin/users").into_response()
}

// ---------------------------------------------------------------------------
// Merchant portal (role = merchant)
// ---------------------------------------------------------------------------

pub struct PortalCheckoutRow {
    pub checkout_id: String,
    pub reference: String,
    pub amount_display: String,
    pub method: String,
    pub transaction_reference: Option<String>,
    pub status: String,
    pub created_at: String,
}

/// Merchants buy verification credit in fixed packages (1 ETB = 1 credit).
const CREDIT_PACKAGES: [i64; 3] = [100, 200, 500];
/// The platform merchant that sells credit (seeded in migration 0005).
const PLATFORM_MERCHANT_ID: &str = "mch_seed_paybridge";

pub struct PortalRecentRow {
    pub checkout_id: String,
    pub reference: String,
    pub amount_display: String,
    pub status: String,
    pub created_at: String,
}

/// A freshly generated payment link, shown on the dashboard after the
/// generator redirects back (`/portal?created={checkout_id}`).
pub struct CreatedLink {
    pub checkout_id: String,
    pub url: String,
    pub reference: String,
    pub amount_display: String,
    pub expires_at: String,
}

#[derive(Template)]
#[template(path = "portal_home.html")]
pub struct PortalHomePage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub onboarding: String,
    pub credits: i64,
    pub today_total: i64,
    pub today_succeeded: i64,
    pub today_failed: i64,
    pub volume_display: String,
    pub pending: i64,
    pub recent: Vec<PortalRecentRow>,
    pub methods: Vec<MerchantMethodRow>,
    pub created_link: Option<CreatedLink>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct PortalHomeQuery {
    /// `?created={checkout_id}`: reveal the just-generated payment link.
    pub created: Option<String>,
    /// `?error={message}`: validation failure from the generator form.
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "portal_checkouts.html")]
pub struct PortalCheckoutsPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub credits: i64,
    pub rows: Vec<PortalCheckoutRow>,
    pub q: String,
    pub status: String,
}

#[derive(Template)]
#[template(path = "portal_checkout.html")]
pub struct PortalCheckoutPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub credits: i64,
    pub checkout_id: String,
    pub reference: String,
    pub amount_display: String,
    pub currency: String,
    pub status: String,
    pub customer: String,
    pub return_url: Option<String>,
    pub method: Option<(String, String)>,
    pub transaction: Option<TransactionView>,
    pub created_at: String,
    pub paid_at: Option<String>,
    pub expires_at: String,
    pub attempts: Vec<AttemptRow>,
    pub events: Vec<EventRow>,
    pub timeline: Vec<TimelineRow>,
    /// Shareable hosted-checkout URL for this checkout.
    pub payment_url: String,
}

pub struct PortalDeliveryListRow {
    pub delivery_id: String,
    pub event_id: String,
    pub event_type: String,
    pub attempt_no: i64,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub created_at: String,
}

pub struct PortalEndpointRow {
    pub endpoint_id: String,
    pub url: String,
    pub status: String,
}

#[derive(Template)]
#[template(path = "portal_webhooks.html")]
pub struct PortalWebhooksPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub credits: i64,
    pub endpoints: Vec<PortalEndpointRow>,
    pub events: Vec<PortalEventRow>,
    pub deliveries: Vec<PortalDeliveryListRow>,
    /// A freshly generated signing secret, rendered exactly once.
    pub new_secret: Option<String>,
}

pub struct PortalEventRow {
    pub event_id: String,
    pub event_type: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
}

#[derive(Template)]
#[template(path = "portal_delivery.html")]
pub struct PortalDeliveryPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub credits: i64,
    pub delivery_id: String,
    pub event_id: String,
    pub event_type: String,
    pub url: String,
    pub attempt_no: i64,
    pub ok: bool,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub created_at: String,
    pub event_status: String,
    pub event_attempts: i64,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
    pub payload: String,
    pub history: Vec<DeliveryRow>,
}

#[derive(Template)]
#[template(path = "portal_keys.html")]
pub struct PortalKeysPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub onboarding: String,
    pub credits: i64,
    pub keys: Vec<MerchantKeyRow>,
    /// A freshly self-generated/rotated key, rendered exactly once.
    pub new_key: Option<String>,
}

#[derive(Template)]
#[template(path = "portal_credits.html")]
pub struct PortalCreditsPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub onboarding: String,
    pub credits: i64,
    pub packages: Vec<i64>,
    pub ledger: Vec<LedgerRow>,
}

/// Merchant home: own stats, recent payments, and payment methods.
pub async fn portal_home(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Query(params): Query<PortalHomeQuery>,
) -> Response {
    let Some((merchant_id, merchant_name, onboarding, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    // The just-generated payment link, ownership-scoped: another merchant's
    // checkout id in the query string renders no banner.
    let created_link = match params.created.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => db::query_as::<(String, i64, String, String)>(
            "SELECT reference, amount_minor, currency, expires_at FROM checkouts \
             WHERE id = ? AND merchant_id = ?",
        )
        .bind(id)
        .bind(&merchant_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .map(|(reference, amount_minor, currency, expires_at)| CreatedLink {
            checkout_id: id.to_string(),
            url: format!("{}/c/{}", state.config.base_url, id),
            amount_display: format!("{} {currency}", format_minor(amount_minor)),
            reference,
            expires_at,
        }),
        None => None,
    };
    let error = params
        .error
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty());

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let by_status: Vec<(String, i64, i64)> = db::query_as(
        "SELECT status, COUNT(*), CAST(COALESCE(SUM(amount_minor), 0) AS BIGINT) \
         FROM checkouts WHERE merchant_id = ? AND created_at >= ? GROUP BY status",
    )
    .bind(&merchant_id)
    .bind(&today)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut today_total = 0i64;
    let mut today_succeeded = 0i64;
    let mut today_failed = 0i64;
    let mut volume_minor = 0i64;
    for (status, count, sum) in by_status {
        today_total += count;
        match status.as_str() {
            "succeeded" => {
                today_succeeded = count;
                volume_minor = sum;
            }
            "failed" => today_failed = count,
            _ => {}
        }
    }
    let (pending,): (i64,) = db::query_as(
        "SELECT COUNT(*) FROM checkouts WHERE merchant_id = ? AND status = 'pending'",
    )
    .bind(&merchant_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0,));

    let recent = match db::query_as::<(String, String, i64, String, String)>(
        "SELECT id, reference, amount_minor, status, created_at FROM checkouts \
         WHERE merchant_id = ? ORDER BY created_at DESC LIMIT 10",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, reference, amount_minor, status, created_at)| PortalRecentRow {
                checkout_id: id,
                reference,
                amount_display: format_minor(amount_minor),
                status,
                created_at,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let methods = match db::query_as::<(String, String, String, String, String, String)>(
        "SELECT id, provider, display_name, account_identifier, instructions, status \
         FROM merchant_payment_methods WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(method_id, provider, display_name, account_identifier, _instructions, status)| {
                    MerchantMethodRow {
                        method_id,
                        provider,
                        display_name,
                        account_identifier,
                        instructions: String::new(),
                        status,
                    }
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalHomePage {
            section: "dashboard",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            onboarding,
            credits,
            today_total,
            today_succeeded,
            today_failed,
            volume_display: format_minor(volume_minor),
            pending,
            recent,
            methods,
            created_link,
            error,
        },
    )
}

async fn portal_merchant(
    state: &AppState,
    sess: &SessionInfo,
) -> Option<(String, String, String, i64)> {
    let merchant_id = sess.user.merchant_id.as_deref()?;
    db::query_as::<(String, String, String, i64)>(
        "SELECT id, name, onboarding_status, credit_balance FROM merchants WHERE id = ?",
    )
    .bind(merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
}

// --- portal: checkouts --------------------------------------------------------

#[derive(Deserialize)]
pub struct PortalCheckoutFilters {
    pub q: Option<String>,
    pub status: Option<String>,
}

pub async fn portal_checkouts(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Query(f): Query<PortalCheckoutFilters>,
) -> Response {
    let Some((merchant_id, merchant_name, _, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let q = f.q.unwrap_or_default().trim().to_string();
    let status = f.status.unwrap_or_default();

    let mut qb = db::query_builder(
        "SELECT c.id, c.reference, c.amount_minor, c.status, c.created_at, COALESCE(pm.display_name, ''), \
                (SELECT t.transaction_reference FROM transactions t \
                 JOIN payments p ON p.id = t.payment_id \
                 WHERE p.checkout_id = c.id AND p.status = 'succeeded' \
                 ORDER BY t.created_at DESC LIMIT 1) \
         FROM checkouts c LEFT JOIN merchant_payment_methods pm ON pm.id = c.selected_method_id WHERE c.merchant_id = ",
    );
    qb.push_bind(&merchant_id);
    if matches!(status.as_str(), "created" | "pending" | "succeeded" | "failed" | "expired") {
        qb.push(" AND c.status = ").push_bind(status.clone());
    }
    if !q.is_empty() {
        let needle = format!("%{q}%");
        qb.push(" AND (c.reference LIKE ")
            .push_bind(needle.clone())
            .push(" OR c.id LIKE ")
            .push_bind(needle.clone())
            .push(" OR EXISTS (SELECT 1 FROM payments p JOIN transactions t ON t.payment_id = p.id \
                   WHERE p.checkout_id = c.id AND t.transaction_reference LIKE ")
            .push_bind(needle)
            .push("))");
    }
    qb.push(" ORDER BY c.created_at DESC LIMIT 50");

    let rows = match qb
        .build_query_as::<(String, String, i64, String, String, String, Option<String>)>()
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(
                |(id, reference, amount_minor, st, created_at, method, transaction_reference)| {
                    PortalCheckoutRow {
                        checkout_id: id,
                        reference,
                        amount_display: format_minor(amount_minor),
                        method,
                        transaction_reference,
                        status: st,
                        created_at,
                    }
                },
            )
            .collect(),
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalCheckoutsPage {
            section: "checkouts",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            credits,
            rows,
            q,
            status,
        },
    )
}

pub async fn portal_checkout_detail(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Path(checkout_id): Path<String>,
) -> Response {
    let Some((merchant_id, merchant_name, _, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    // Ownership first: other merchants' checkouts look like unknown ones.
    let Some(row) = db::query_as::<
        (
            String,
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT reference, amount_minor, currency, status, customer_name, customer_email, \
                return_url, expires_at, created_at, paid_at, selected_method_id \
         FROM checkouts WHERE id = ? AND merchant_id = ?",
    )
    .bind(&checkout_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };
    let (
        reference,
        amount_minor,
        currency,
        status,
        customer_name,
        customer_email,
        return_url,
        expires_at,
        created_at,
        paid_at,
        selected_method_id,
    ) = row;

    let method = match &selected_method_id {
        Some(method_id) => db::query_as::<(String, String)>(
            "SELECT provider, display_name FROM merchant_payment_methods WHERE id = ?",
        )
        .bind(method_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten(),
        None => None,
    };

    let transaction = db::query_as::<(String, i64, String, String, String)>(
        "SELECT t.transaction_reference, t.amount_minor, t.currency, t.recipient, t.occurred_at \
         FROM transactions t JOIN payments p ON p.id = t.payment_id \
         WHERE p.checkout_id = ? AND p.status = 'succeeded' \
         ORDER BY t.created_at DESC LIMIT 1",
    )
    .bind(&checkout_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|(reference, amount_minor, txn_currency, recipient, occurred_at)| TransactionView {
        reference,
        amount_display: format_minor(amount_minor),
        currency: txn_currency,
        recipient,
        occurred_at,
    });

    let attempts = match db::query_as::<(String, Option<String>, String, String)>(
        "SELECT outcome, detail, transaction_reference, created_at FROM payment_attempts \
         WHERE checkout_id = ? ORDER BY created_at DESC LIMIT 20",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(outcome, detail, transaction_reference, created_at)| AttemptRow {
                outcome,
                detail,
                transaction_reference,
                created_at,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let mut events: Vec<EventRow> = db::query_as::<
        (String, String, String, i64, String, Option<String>, String),
    >(
        "SELECT id, event_type, status, attempts, next_attempt_at, last_error, payload \
         FROM outbox_messages WHERE aggregate_id = ? ORDER BY created_at DESC",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, event_type, ev_status, ev_attempts, next_attempt_at, last_error, payload)| {
                EventRow {
                    event_id: id.clone(),
                    event_type,
                    status: ev_status,
                    attempts: ev_attempts,
                    next_attempt_at,
                    last_error,
                    payload,
                    deliveries: Vec::new(),
                }
            })
            .collect()
    })
    .unwrap_or_default();

    let all_deliveries = match db::query_as::<
        (String, String, i64, Option<i64>, Option<String>, Option<i64>, String),
    >(
        "SELECT d.outbox_id, d.id, d.attempt_no, d.status_code, d.error, d.duration_ms, d.created_at \
         FROM webhook_deliveries d JOIN outbox_messages o ON o.id = d.outbox_id \
         WHERE o.aggregate_id = ? ORDER BY d.attempt_no",
    )
    .bind(&checkout_id)
    .fetch_all(&state.pool)
    .await
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    for (outbox_id, delivery_id, attempt_no, status_code, error, duration_ms, created_at) in
        all_deliveries
    {
        if let Some(event) = events.iter_mut().find(|e| e.event_id == outbox_id) {
            event.deliveries.push(DeliveryRow {
                delivery_id,
                attempt_no,
                status_code,
                error,
                duration_ms,
                created_at,
            });
        }
    }

    let customer = [customer_name, customer_email]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" \u{b7} ");

    let timeline = checkout_timeline(&state.pool, &checkout_id, &created_at, &paid_at).await;
    let payment_url = format!("{}/c/{}", state.config.base_url, checkout_id);
    page(
        StatusCode::OK,
        PortalCheckoutPage {
            section: "checkouts",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            credits,
            checkout_id,
            reference,
            amount_display: format_minor(amount_minor),
            currency,
            status,
            customer,
            return_url,
            method,
            transaction,
            created_at,
            paid_at,
            expires_at,
            attempts,
            events,
            timeline,
            payment_url,
        },
    )
}

// --- portal: payment link generator -------------------------------------------

#[derive(Deserialize)]
pub struct PaymentLinkForm {
    pub csrf: String,
    /// Decimal ETB amount, e.g. "500" or "500.50".
    pub amount: String,
    /// Merchant-side reference; auto-generated when left blank.
    pub reference: Option<String>,
    pub customer_name: Option<String>,
    pub customer_email: Option<String>,
    pub return_url: Option<String>,
    /// "1h", "24h" (default) or "7d".
    pub expires_in: Option<String>,
}

/// Back to the dashboard with the error in the query string (refresh clears it).
fn redirect_portal_error(message: &str) -> Response {
    let q = percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC);
    Redirect::to(&format!("/portal?error={q}")).into_response()
}

/// No-code checkout creation: the merchant generates a shareable hosted
/// payment link (`{base_url}/c/{checkout_id}`) straight from the dashboard.
/// Mirrors the API's gates (active merchant, prepaid credit) and validation.
pub async fn portal_payment_link_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<PaymentLinkForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some(merchant_id) = sess.user.merchant_id.clone() else {
        return not_found();
    };
    let Some((merchant_status, credits)) = db::query_as::<(String, i64)>(
        "SELECT status, credit_balance FROM merchants WHERE id = ?",
    )
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };
    if merchant_status != "active" {
        return redirect_portal_error("Your merchant account is not active — contact support.");
    }
    // Same prepaid gate as the API: never collect a payment that cannot be verified.
    if credits < 1 {
        return redirect_portal_error(
            "Your verification credit is exhausted. Buy more credit to continue.",
        );
    }

    let amount_minor = match crate::money::decimal_to_minor(form.amount.trim()) {
        Ok(minor) if minor > 0 => minor,
        Ok(_) => return redirect_portal_error("Amount must be greater than zero."),
        Err(_) => {
            return redirect_portal_error(
                "Enter a valid amount with at most 2 decimal places, e.g. 500 or 500.50.",
            )
        }
    };

    let reference = match form.reference.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => r.to_string(),
        None => new_id("ref"),
    };
    let customer_name = form
        .customer_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let customer_email = form
        .customer_email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let return_url = match form.return_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => match url::Url::parse(url) {
            Ok(parsed) if parsed.scheme() == "http" || parsed.scheme() == "https" => {
                Some(url.to_string())
            }
            _ => return redirect_portal_error("Return URL must be an absolute http(s) URL."),
        },
        None => None,
    };

    let ttl_secs = match form.expires_in.as_deref() {
        Some("1h") => 3600,
        Some("7d") => 7 * 86_400,
        _ => 86_400,
    }
    .min(state.config.checkout_ttl_max.as_secs() as i64);
    let expires_at = crate::ids::to_iso(chrono::Utc::now() + chrono::Duration::seconds(ttl_secs));

    let checkout_id = new_id("chk");
    if let Err(e) = db::query(
        "INSERT INTO checkouts \
         (id, merchant_id, reference, amount_minor, currency, status, customer_name, customer_email, return_url, selected_method_id, expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, 'ETB', 'created', ?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(&checkout_id)
    .bind(&merchant_id)
    .bind(&reference)
    .bind(amount_minor)
    .bind(&customer_name)
    .bind(&customer_email)
    .bind(&return_url)
    .bind(&expires_at)
    .bind(now_iso())
    .bind(now_iso())
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_link.created",
        "checkout",
        &checkout_id,
        Some(format!(
            "{{\"reference\":\"{reference}\",\"amount_minor\":{amount_minor},\"self\":true}}"
        )),
    )
    .await;

    Redirect::to(&format!("/portal?created={checkout_id}")).into_response()
}

// --- portal: webhooks ---------------------------------------------------------

pub async fn portal_webhooks(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    portal_webhooks_view(&state, &sess, None).await
}

async fn portal_webhooks_view(
    state: &AppState,
    sess: &SessionInfo,
    new_secret: Option<String>,
) -> Response {
    let Some((merchant_id, merchant_name, _, credits)) = portal_merchant(state, sess).await else {
        return not_found();
    };

    let endpoints = match db::query_as::<(String, String, String)>(
        "SELECT id, url, status FROM webhook_endpoints WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(endpoint_id, url, status)| PortalEndpointRow {
                endpoint_id,
                url,
                status,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    // All payment events for this merchant's checkouts, including
    // dead-lettered ones that never produced a delivery row.
    let events = match db::query_as::<
        (String, String, String, i64, String, Option<String>),
    >(
        "SELECT o.id, o.event_type, o.status, o.attempts, o.next_attempt_at, o.last_error          FROM outbox_messages o          JOIN checkouts c ON c.id = o.aggregate_id          WHERE c.merchant_id = ?          ORDER BY o.created_at DESC LIMIT 50",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(event_id, event_type, status, attempts, next_attempt_at, last_error)| {
                PortalEventRow {
                    event_id,
                    event_type,
                    status,
                    attempts,
                    next_attempt_at,
                    last_error,
                }
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    let deliveries = match db::query_as::<
        (String, String, String, i64, Option<i64>, Option<String>, String),
    >(
        "SELECT d.id, o.id, o.event_type, d.attempt_no, d.status_code, d.error, d.created_at \
         FROM webhook_deliveries d \
         JOIN outbox_messages o ON o.id = d.outbox_id \
         JOIN webhook_endpoints e ON e.id = d.endpoint_id \
         WHERE e.merchant_id = ? \
         ORDER BY d.created_at DESC LIMIT 50",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(delivery_id, event_id, event_type, attempt_no, status_code, error, created_at)| {
                    PortalDeliveryListRow {
                        delivery_id,
                        event_id,
                        event_type,
                        attempt_no,
                        status_code,
                        error,
                        created_at,
                    }
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalWebhooksPage {
            section: "webhooks",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            credits,
            endpoints,
            events,
            deliveries,
            new_secret,
        },
    )
}

// --- portal: webhook endpoint self-service -------------------------------------
// Merchants register their own delivery URL. One ACTIVE endpoint per merchant
// (the dispatcher delivers to a single active endpoint); signing secrets are
// generated server-side and shown exactly once.

fn generate_webhook_secret() -> String {
    format!("whsec_{}{}", ulid::Ulid::new(), ulid::Ulid::new())
}

fn valid_webhook_url(raw: &str) -> Result<String, Response> {
    let trimmed = raw.trim().to_string();
    let parsed = url::Url::parse(&trimmed)
        .map_err(|_| bad_request("endpoint URL must be an absolute http(s) URL"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(bad_request("endpoint URL must be http(s)"));
    }
    if trimmed.len() > 500 {
        return Err(bad_request("endpoint URL is too long"));
    }
    Ok(trimmed)
}

#[derive(Deserialize)]
pub struct PortalWebhookCreateForm {
    pub csrf: String,
    pub url: String,
}

/// Register the merchant's webhook endpoint. A signing secret is generated
/// and shown once — deliveries are signed with `X-PayBridge-Signature`.
pub async fn portal_webhook_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<PortalWebhookCreateForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let url = match valid_webhook_url(&form.url) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let (active,): (i64,) = db::query_as(
        "SELECT COUNT(*) FROM webhook_endpoints WHERE merchant_id = ? AND status = 'active'",
    )
    .bind(&merchant_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0,));
    if active > 0 {
        return bad_request("an active endpoint already exists — disable it before registering another");
    }

    let secret = generate_webhook_secret();
    if let Err(e) = db::query(
        "INSERT INTO webhook_endpoints (id, merchant_id, url, secret, status, created_at) \
         VALUES (?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("wh"))
    .bind(&merchant_id)
    .bind(&url)
    .bind(&secret)
    .bind(now_iso())
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "webhook_endpoint.created",
        "merchant",
        &merchant_id,
        Some(format!("{{\"url\":\"{url}\",\"self\":true}}")),
    )
    .await;

    portal_webhooks_view(&state, &sess, Some(secret)).await
}

#[derive(Deserialize)]
pub struct PortalWebhookStatusForm {
    pub csrf: String,
    pub action: String,
}

/// Enable/disable one of the merchant's own endpoints.
pub async fn portal_webhook_status(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(endpoint_id): Path<String>,
    Form(form): Form<PortalWebhookStatusForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let next_status = match form.action.as_str() {
        "enable" => "active",
        "disable" => "disabled",
        _ => return bad_request("unknown action"),
    };

    let updated = db::query(
        "UPDATE webhook_endpoints SET status = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(next_status)
    .bind(&endpoint_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await;
    let Ok(updated) = updated else {
        return db_error(updated.err().unwrap());
    };
    if updated.rows_affected() == 0 {
        return not_found();
    }

    let action =
        if next_status == "active" { "webhook_endpoint.enabled" } else { "webhook_endpoint.disabled" };
    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        action,
        "webhook_endpoint",
        &endpoint_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"self\":true}}")),
    )
    .await;

    Redirect::to("/portal/webhooks").into_response()
}

#[derive(Deserialize)]
pub struct PortalWebhookSecretForm {
    pub csrf: String,
}

/// Rotate the endpoint's signing secret. The old secret stops verifying
/// immediately; the new one is shown once.
pub async fn portal_webhook_secret(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(endpoint_id): Path<String>,
    Form(form): Form<PortalWebhookSecretForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let exists: Option<(String,)> = db::query_as(
        "SELECT id FROM webhook_endpoints WHERE id = ? AND merchant_id = ?",
    )
    .bind(&endpoint_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    if exists.is_none() {
        return not_found();
    }

    let secret = generate_webhook_secret();
    if let Err(e) = db::query("UPDATE webhook_endpoints SET secret = ? WHERE id = ?")
        .bind(&secret)
        .bind(&endpoint_id)
        .execute(&state.pool)
        .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "webhook_endpoint.secret_rotated",
        "webhook_endpoint",
        &endpoint_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"self\":true}}")),
    )
    .await;

    portal_webhooks_view(&state, &sess, Some(secret)).await
}

pub async fn portal_delivery_detail(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    Path(delivery_id): Path<String>,
) -> Response {
    let Some((merchant_id, merchant_name, _, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    // Ownership: only deliveries that went to this merchant's endpoints.
    let Some((outbox_id, attempt_no, status_code, error, duration_ms, created_at)) =
        db::query_as::<
            (String, i64, Option<i64>, Option<String>, Option<i64>, String),
        >(
            "SELECT d.outbox_id, d.attempt_no, d.status_code, d.error, d.duration_ms, d.created_at \
             FROM webhook_deliveries d \
             JOIN webhook_endpoints e ON e.id = d.endpoint_id \
             WHERE d.id = ? AND e.merchant_id = ?",
        )
        .bind(&delivery_id)
        .bind(&merchant_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };

    let Some((event_type, event_status, event_attempts, next_attempt_at, last_error, payload)) =
        db::query_as::<(String, String, i64, String, Option<String>, String)>(
            "SELECT event_type, status, attempts, next_attempt_at, last_error, payload \
             FROM outbox_messages WHERE id = ?",
        )
        .bind(&outbox_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };

    let url = db::query_as::<(String,)>(
        "SELECT url FROM webhook_endpoints WHERE merchant_id = ? AND status = 'active' LIMIT 1",
    )
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|(u,)| u)
    .unwrap_or_default();

    let history = match db::query_as::<(String, i64, Option<i64>, Option<String>, Option<i64>, String)>(
        "SELECT id, attempt_no, status_code, error, duration_ms, created_at \
         FROM webhook_deliveries WHERE outbox_id = ? ORDER BY attempt_no",
    )
    .bind(&outbox_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(delivery_id, attempt_no, status_code, error, duration_ms, created_at)| DeliveryRow {
                    delivery_id,
                    attempt_no,
                    status_code,
                    error,
                    duration_ms,
                    created_at,
                },
            )
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalDeliveryPage {
            section: "webhooks",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            credits,
            delivery_id,
            event_id: outbox_id,
            event_type,
            url,
            attempt_no,
            ok: status_code.map(|c| (200..300).contains(&c)).unwrap_or(false),
            status_code,
            error,
            duration_ms,
            created_at,
            event_status,
            event_attempts,
            next_attempt_at,
            last_error,
            payload,
            history,
        },
    )
}

#[derive(Deserialize)]
pub struct PortalRetryForm {
    pub csrf: String,
}

/// Retry one of the merchant's own webhook deliveries.
pub async fn portal_delivery_retry(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(delivery_id): Path<String>,
    Form(form): Form<PortalRetryForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let Some((event_id,)): Option<(String,)> = db::query_as(
        "SELECT d.outbox_id FROM webhook_deliveries d \
         JOIN webhook_endpoints e ON e.id = d.endpoint_id \
         WHERE d.id = ? AND e.merchant_id = ?",
    )
    .bind(&delivery_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    else {
        return not_found();
    };

    if let Err(e) = db::query(
        "UPDATE outbox_messages \
         SET status = 'pending', attempts = CASE WHEN attempts - 1 > 0 THEN attempts - 1 ELSE 0 END, next_attempt_at = ? \
         WHERE id = ?",
    )
    .bind(now_iso())
    .bind(&event_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "webhook.retried",
        "webhook_event",
        &event_id,
        Some(format!("{{\"delivery\":\"{delivery_id}\",\"self\":true}}")),
    )
    .await;

    Redirect::to(&format!("/portal/webhooks/deliveries/{delivery_id}")).into_response()
}

// --- portal: API keys -----------------------------------------------------------

pub async fn portal_keys_page(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    portal_keys_view(&state, &sess, None).await
}

async fn portal_keys_view(state: &AppState, sess: &SessionInfo, new_key: Option<String>) -> Response {
    let Some((merchant_id, merchant_name, onboarding, credits)) = portal_merchant(state, sess).await else {
        return not_found();
    };

    let keys = match db::query_as::<(String, String, String, Option<String>)>(
        "SELECT id, prefix, created_at, revoked_at FROM merchant_api_keys \
         WHERE merchant_id = ? ORDER BY created_at DESC",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(key_id, prefix, created_at, revoked_at)| MerchantKeyRow {
                key_id,
                prefix,
                created_at,
                active: revoked_at.is_none(),
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalKeysPage {
            section: "keys",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            onboarding,
            credits,
            keys,
            new_key,
        },
    )
}

#[derive(Deserialize)]
pub struct PortalKeyForm {
    pub csrf: String,
}

/// Self-serve API key: merchants with credit generate their own keys. The
/// secret is shown once on the rendered portal page.
pub async fn portal_key_generate(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<PortalKeyForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, onboarding, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    if onboarding != "approved" || credits < 1 {
        return bad_request("buy credit first — API keys are enabled once your account has credit");
    }
    let secret = match insert_api_key(&state.pool, &merchant_id, "test").await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.created",
        "merchant",
        &merchant_id,
        Some(format!("{{\"kind\":\"test\",\"prefix\":\"{}\",\"self\":true}}", &secret[..12])),
    )
    .await;

    portal_keys_view(&state, &sess, Some(secret)).await
}

/// Revoke one of the merchant's own keys.
pub async fn portal_key_revoke(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    Form(form): Form<PortalKeyForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let prefix: Option<(String,)> = db::query_as(
        "SELECT prefix FROM merchant_api_keys WHERE id = ? AND merchant_id = ?",
    )
    .bind(&key_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((prefix,)) = prefix else {
        return not_found();
    };

    if let Err(e) = db::query(
        "UPDATE merchant_api_keys SET revoked_at = ? \
         WHERE id = ? AND merchant_id = ? AND revoked_at IS NULL",
    )
    .bind(now_iso())
    .bind(&key_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.revoked",
        "merchant",
        &merchant_id,
        Some(format!("{{\"key\":\"{key_id}\",\"prefix\":\"{prefix}\",\"self\":true}}")),
    )
    .await;

    Redirect::to("/portal/keys").into_response()
}

/// Rotate one of the merchant's own keys (old dies, new secret shown once).
pub async fn portal_key_rotate(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    Form(form): Form<PortalKeyForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let old: Option<(String,)> = db::query_as(
        "SELECT prefix FROM merchant_api_keys WHERE id = ? AND merchant_id = ? AND revoked_at IS NULL",
    )
    .bind(&key_id)
    .bind(&merchant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((old_prefix,)) = old else {
        return not_found();
    };
    let kind = old_prefix
        .strip_prefix("pb_sk_")
        .and_then(|rest| rest.split('_').next())
        .unwrap_or("test")
        .to_string();

    let mut db = match state.pool.begin().await {
        Ok(db) => db,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db::query(
        "UPDATE merchant_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now_iso())
    .bind(&key_id)
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    let new_secret = match insert_api_key_tx(&mut db, &merchant_id, &kind).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db.commit().await {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "api_key.rotated",
        "merchant",
        &merchant_id,
        Some(format!(
            "{{\"key\":\"{key_id}\",\"old_prefix\":\"{old_prefix}\",\"new_prefix\":\"{}\",\"self\":true}}",
            &new_secret[..12]
        )),
    )
    .await;

    portal_keys_view(&state, &sess, Some(new_secret)).await
}

// --- portal: credits ------------------------------------------------------------

pub struct LedgerRow {
    pub delta: i64,
    pub reason: String,
    pub checkout_id: Option<String>,
    pub created_at: String,
}

pub async fn portal_credits_page(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    let Some((merchant_id, merchant_name, onboarding, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let ledger = match db::query_as::<(i64, String, Option<String>, String)>(
        "SELECT delta, reason, checkout_id, created_at FROM credit_ledger \
         WHERE merchant_id = ? ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(delta, reason, checkout_id, created_at)| LedgerRow {
                delta,
                reason,
                checkout_id,
                created_at,
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalCreditsPage {
            section: "credits",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            onboarding,
            credits,
            packages: CREDIT_PACKAGES.to_vec(),
            ledger,
        },
    )
}

// --- portal: payment methods ---------------------------------------------------
// Merchants add their own provider + receiving account; the customer-facing
// steps come from central provider config and are never merchant-authored.

#[derive(Template)]
#[template(path = "portal_methods.html")]
pub struct PortalMethodsPage {
    pub section: &'static str,
    pub csrf: String,
    pub email: String,
    pub merchant_name: String,
    pub credits: i64,
    pub methods: Vec<MerchantMethodRow>,
    pub providers: Vec<(String, String)>,
}

pub async fn portal_methods_page(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
) -> Response {
    let Some((merchant_id, merchant_name, _, credits)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };

    let methods = match db::query_as::<(String, String, String, String, String)>(
        "SELECT id, provider, display_name, account_identifier, status \
         FROM merchant_payment_methods WHERE merchant_id = ? ORDER BY created_at",
    )
    .bind(&merchant_id)
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(method_id, provider, display_name, account_identifier, status)| {
                MerchantMethodRow {
                    method_id,
                    provider,
                    display_name,
                    account_identifier,
                    instructions: String::new(),
                    status,
                }
            })
            .collect()
    })
     {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    page(
        StatusCode::OK,
        PortalMethodsPage {
            section: "methods",
            csrf: sess.token.clone(),
            email: sess.user.email.clone(),
            merchant_name,
            credits,
            methods,
            providers: PROVIDERS
                .iter()
                .map(|(p, n)| (p.to_string(), n.to_string()))
                .collect(),
        },
    )
}

#[derive(Deserialize)]
pub struct PortalMethodCreateForm {
    pub csrf: String,
    pub provider: String,
    pub display_name: Option<String>,
    pub account_identifier: String,
}

/// Add a receiving account for a provider. The customer-facing steps are
/// filled from central provider config — the form has no instructions field.
pub async fn portal_method_create(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<PortalMethodCreateForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let Some((_, default_name)) = PROVIDERS.iter().find(|(p, _)| *p == form.provider.as_str())
    else {
        return bad_request("unknown provider");
    };
    let account = form.account_identifier.trim().to_string();
    if account.is_empty() {
        return bad_request("receiving account is required");
    }
    let display_name = form
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_name)
        .to_string();
    let instructions = provider_default_instructions(&state.pool, &form.provider).await;

    if let Err(e) = db::query(
        "INSERT INTO merchant_payment_methods \
         (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
    )
    .bind(new_id("mpm"))
    .bind(&merchant_id)
    .bind(&form.provider)
    .bind(&display_name)
    .bind(&account)
    .bind(&instructions)
    .bind(now_iso())
    .execute(&state.pool)
    .await
    {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.added",
        "merchant",
        &merchant_id,
        Some(format!(
            "{{\"provider\":\"{}\",\"account\":\"{account}\",\"self\":true}}",
            form.provider
        )),
    )
    .await;

    Redirect::to("/portal/methods").into_response()
}

#[derive(Deserialize)]
pub struct PortalMethodStatusForm {
    pub csrf: String,
    pub action: String,
}

/// Enable/disable one of the merchant's own methods.
pub async fn portal_method_status(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(method_id): Path<String>,
    Form(form): Form<PortalMethodStatusForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let next_status = match form.action.as_str() {
        "enable" => "active",
        "disable" => "disabled",
        _ => return bad_request("unknown action"),
    };

    let updated = db::query(
        "UPDATE merchant_payment_methods SET status = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(next_status)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await;
    let Ok(updated) = updated else {
        return db_error(updated.err().unwrap());
    };
    if updated.rows_affected() == 0 {
        return not_found();
    }

    let action =
        if next_status == "active" { "payment_method.enabled" } else { "payment_method.disabled" };
    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        action,
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"self\":true}}")),
    )
    .await;

    Redirect::to("/portal/methods").into_response()
}

#[derive(Deserialize)]
pub struct PortalMethodAccountForm {
    pub csrf: String,
    pub account_identifier: String,
}

/// Update the receiving wallet of one of the merchant's own methods. Audited;
/// the credit ledger + transactions keep the history for disputes.
pub async fn portal_method_account(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(method_id): Path<String>,
    Form(form): Form<PortalMethodAccountForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let account = form.account_identifier.trim().to_string();
    if account.is_empty() {
        return bad_request("receiving account is required");
    }

    let updated = db::query(
        "UPDATE merchant_payment_methods SET account_identifier = ? \
         WHERE id = ? AND merchant_id = ?",
    )
    .bind(&account)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await;
    let Ok(updated) = updated else {
        return db_error(updated.err().unwrap());
    };
    if updated.rows_affected() == 0 {
        return not_found();
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.account_changed",
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"account\":\"{account}\",\"self\":true}}")),
    )
    .await;

    Redirect::to("/portal/methods").into_response()
}

#[derive(Deserialize)]
pub struct PortalMethodNameForm {
    pub csrf: String,
    pub display_name: String,
}

/// Rename one of the merchant's own methods — this is the name customers see
/// on the checkout ("yaya", "Acme Telebirr", …), independent of the provider.
pub async fn portal_method_name(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Path(method_id): Path<String>,
    Form(form): Form<PortalMethodNameForm>,
) -> Response {
    if !csrf_ok(&sess, &form.csrf) {
        return bad_request("expired session; go back and retry");
    }
    let Some((merchant_id, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let name = form.display_name.trim().to_string();
    if name.is_empty() || name.len() > 60 {
        return bad_request("display name must be 1-60 characters");
    }

    let updated = db::query(
        "UPDATE merchant_payment_methods SET display_name = ? WHERE id = ? AND merchant_id = ?",
    )
    .bind(&name)
    .bind(&method_id)
    .bind(&merchant_id)
    .execute(&state.pool)
    .await;
    let Ok(updated) = updated else {
        return db_error(updated.err().unwrap());
    };
    if updated.rows_affected() == 0 {
        return not_found();
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "payment_method.renamed",
        "payment_method",
        &method_id,
        Some(format!("{{\"merchant\":\"{merchant_id}\",\"name\":\"{name}\",\"self\":true}}")),
    )
    .await;

    Redirect::to("/portal/methods").into_response()
}

#[derive(Deserialize)]
pub struct CreditsBuyForm {
    pub csrf: String,
    pub credits: i64,
}

/// Buy credit: creates a normal hosted checkout against the platform merchant
/// (the merchant pays via wallet + transaction reference, verified by the same
/// engine). Settling that checkout credits the buyer — see
/// domain::consume_transaction.
pub async fn credits_buy(
    State(state): State<AppState>,
    Extension(sess): Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<CreditsBuyForm>,
) -> Response {
    if !CREDIT_PACKAGES.contains(&form.credits) {
        return bad_request("choose a credit package");
    }
    let Some((_, _, _, _)) = portal_merchant(&state, &sess).await else {
        return not_found();
    };
    let merchant_id = sess.user.merchant_id.clone().unwrap_or_default();

    let checkout_id = new_id("chk");
    let amount_minor = form.credits * 100;
    let now = now_iso();
    let expires_at = crate::ids::to_iso(chrono::Utc::now() + chrono::Duration::hours(24));

    let mut db = match state.pool.begin().await {
        Ok(db) => db,
        Err(e) => return db_error(e),
    };
    if let Err(e) = db::query(
        "INSERT INTO checkouts \
         (id, merchant_id, reference, amount_minor, currency, status, return_url, expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, 'ETB', 'created', ?, ?, ?, ?)",
    )
    .bind(&checkout_id)
    .bind(PLATFORM_MERCHANT_ID)
    .bind(format!("CREDITS-{merchant_id}"))
    .bind(amount_minor)
    .bind(format!("{}/portal", state.config.base_url))
    .bind(&expires_at)
    .bind(&now)
    .bind(&now)
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    if let Err(e) = db::query(
        "INSERT INTO credit_purchases (id, merchant_id, checkout_id, credits, amount_minor, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(new_id("crp"))
    .bind(&merchant_id)
    .bind(&checkout_id)
    .bind(form.credits)
    .bind(amount_minor)
    .bind(&now)
    .execute(&mut *db)
    .await
    {
        return db_error(e);
    }
    if let Err(e) = db.commit().await {
        return db_error(e);
    }

    audit(
        &state.pool,
        &sess.user.email,
        client_ip(&headers).as_deref(),
        "credits.purchase_started",
        "merchant",
        &merchant_id,
        Some(format!("{{\"credits\":{},\"checkout\":\"{checkout_id}\"}}", form.credits)),
    )
    .await;

    Redirect::to(&format!("/c/{checkout_id}")).into_response()
}

// ---------------------------------------------------------------------------
// Shared responses
// ---------------------------------------------------------------------------

fn db_error(e: sqlx::Error) -> Response {
    tracing::error!(error = %e, "admin page: database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Check the server logs.",
    )
        .into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Your role does not allow this action.",
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}
