//! Hosted checkout pages: server-rendered HTML, no SPA, no merchant data.
//! Flow: GET /c/{id} -> pick method (POST /method) -> instructions + reference
//! input -> POST /verify -> redirect (PRG) back to the page or the merchant's
//! returnUrl. CSRF via double-submit cookie.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;
use std::collections::HashMap;

use crate::domain::{self, VerifyResult};
use crate::ids::new_id;
use crate::money::format_minor;
use crate::state::AppState;

const CSRF_COOKIE: &str = "pb_csrf";

pub async fn index() -> Html<&'static str> {
    Html("<h1>PayBridge</h1><p>Hosted checkout service. Health check: <code>/health</code></p>")
}

/// 303 See Other as a full `Response` (POST -> GET redirect, PRG pattern).
fn see_other(path: String) -> Response {
    Redirect::to(&path).into_response()
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split("; ")
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('=').map(str::to_owned))
}

fn set_cookie_on(mut response: Response, cookie: String) -> Response {
    if let Ok(value) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn simple_page(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>PayBridge</title></head>\
             <body style=\"font-family:system-ui;display:flex;justify-content:center;padding:60px 20px\">\
             <div><h1>PayBridge</h1><p>{message}</p></div></body></html>"
        )),
    )
        .into_response()
}

fn db_error_page(e: sqlx::Error) -> Response {
    tracing::error!(error = %e, "hosted page: database error");
    simple_page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong. Please try again.")
}

#[derive(Template)]
#[template(path = "checkout.html")]
pub struct CheckoutPage {
    pub merchant_name: String,
    pub reference: String,
    pub amount_display: String,
    pub checkout_id: String,
    pub csrf: String,
    /// 1 = choose method, 2 = pay + verify, 3 = done.
    pub step: u8,
    pub show_methods: bool,
    pub show_instructions: bool,
    pub show_succeeded: bool,
    pub show_expired: bool,
    pub show_failed: bool,
    pub show_change_method: bool,
    pub items: Vec<ItemView>,
    pub has_items: bool,
    pub slides: Vec<SlideView>,
    pub has_slides: bool,
    pub methods: Vec<MethodView>,
    pub selected: Option<MethodView>,
    pub error_message: Option<String>,
    pub paid_reference: Option<String>,
}

pub struct ItemView {
    pub name: String,
    pub quantity: i64,
    pub unit_price_display: String,
    pub line_total_display: String,
}

/// One walkthrough image ("how to pay in the app") for the selected provider.
pub struct SlideView {
    pub src: String,
    pub caption: String,
}

pub struct MethodView {
    pub id: String,
    pub display_name: String,
    pub account_identifier: String,
    pub instruction_lines: Vec<String>,
}

/// Load `static/pay/{provider}/slides.json` — a list of
/// `{ "image": "...", "caption": "..." }` entries shown as the "how to pay in
/// the app" slideshow. Missing manifest or files -> no slideshow (the plain
/// numbered steps are shown instead), so merchants can add screenshots later
/// without code changes.
fn load_slides(static_dir: &std::path::Path, provider: &str) -> Vec<SlideView> {
    #[derive(Deserialize)]
    struct SlideEntry {
        image: String,
        caption: String,
    }

    // Provider comes from a CHECK constraint in the DB; still, never let it
    // escape the slides directory.
    if !provider.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Vec::new();
    }
    let dir = static_dir.join("pay").join(provider);
    let Ok(raw) = std::fs::read_to_string(dir.join("slides.json")) else {
        return Vec::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<SlideEntry>>(&raw) else {
        tracing::warn!(provider, "invalid slides.json; skipping slideshow");
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|e| {
            !e.image.is_empty()
                && e.image.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                && !e.image.contains("..")
                && dir.join(&e.image).is_file()
        })
        .map(|e| SlideView {
            src: format!("/static/pay/{provider}/{}", e.image),
            caption: e.caption,
        })
        .collect()
}

fn error_text(reason: &str, amount_display: &str) -> String {
    match reason {
        "amount_mismatch" => format!(
            "The transaction we found is for a different amount. Make sure you send exactly {amount_display}."
        ),
        "transaction_not_found" => {
            "We could not find that transaction reference. Double-check it in your wallet app and try again."
                .to_string()
        }
        "transaction_not_successful" => {
            "That transaction is not completed yet. Confirm the payment went through, then try again."
                .to_string()
        }
        "transaction_too_old" => {
            "That transaction happened before this checkout was created. Please pay again and use the new reference."
                .to_string()
        }
        "recipient_mismatch" => {
            "The payment went to a different account than the one shown. Pay exactly the number shown above."
                .to_string()
        }
        "transaction_already_used" => {
            "That transaction reference has already been used for another payment.".to_string()
        }
        "too_many_attempts" => "Too many verification attempts. Please contact support or try again later."
            .to_string(),
        "attempt_cooldown" => "Please wait a few seconds before trying again.".to_string(),
        "verification_service_unavailable" => {
            "Payment verification is temporarily unavailable. Please try again in a moment.".to_string()
        }
        "checkout_not_pending" => "This checkout is no longer payable.".to_string(),
        _ => "Something went wrong. Please try again.".to_string(),
    }
}

pub async fn checkout_page(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let existing_csrf = read_cookie(&headers, CSRF_COOKIE);
    let set_cookie = existing_csrf.is_none();
    let csrf = existing_csrf.unwrap_or_else(|| new_id("csrf"));

    let checkout = match domain::load_checkout(&state.pool, &checkout_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return simple_page(StatusCode::NOT_FOUND, "This checkout link does not exist."),
        Err(e) => return db_error_page(e),
    };

    let merchant_name = sqlx::query_as::<_, (String,)>("SELECT name FROM merchants WHERE id = ?")
        .bind(&checkout.merchant_id)
        .fetch_one(&state.pool)
        .await
        .map(|(n,)| n)
        .unwrap_or_else(|_| "Merchant".to_string());

    let amount_display = format!("{} {}", format_minor(checkout.amount_minor), checkout.currency);

    let item_rows = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT name, quantity, unit_price_minor FROM checkout_items WHERE checkout_id = ? ORDER BY id",
    )
    .bind(&checkout.id)
    .fetch_all(&state.pool)
    .await;
    let items = match item_rows {
        Ok(rows) => rows
            .into_iter()
            .map(|(name, quantity, unit_price)| ItemView {
                name,
                quantity,
                unit_price_display: format_minor(unit_price),
                line_total_display: format_minor(unit_price * quantity),
            })
            .collect::<Vec<_>>(),
        Err(e) => return db_error_page(e),
    };
    let has_items = !items.is_empty();

    // `?change=1` re-opens method selection on a pending checkout.
    let wants_change = params.contains_key("change");
    let needs_methods =
        checkout.status == "created" || (checkout.status == "pending" && checkout.selected_method_id.is_none());
    let show_methods = needs_methods || (wants_change && checkout.status == "pending");
    let mut methods = Vec::new();
    if show_methods {
        match sqlx::query_as::<_, (String, String)>(
            "SELECT id, display_name FROM merchant_payment_methods \
             WHERE merchant_id = ? AND status = 'active' ORDER BY created_at",
        )
        .bind(&checkout.merchant_id)
        .fetch_all(&state.pool)
        .await
        {
            Ok(rows) => {
                methods = rows
                    .into_iter()
                    .map(|(id, display_name)| MethodView {
                        id,
                        display_name,
                        account_identifier: String::new(),
                        instruction_lines: Vec::new(),
                    })
                    .collect();
            }
            Err(e) => return db_error_page(e),
        }
    }

    let mut selected = None;
    let mut slides = Vec::new();
    if let Some(method_id) = &checkout.selected_method_id {
        if let Ok(Some(m)) = domain::load_method(&state.pool, method_id).await {
            slides = load_slides(&state.config.static_dir, &m.provider);
            selected = Some(MethodView {
                id: m.id,
                display_name: m.display_name,
                account_identifier: m.account_identifier,
                instruction_lines: m.instructions.lines().map(str::to_string).collect(),
            });
        }
    }
    let has_slides = !slides.is_empty();

    let paid_reference = if checkout.status == "succeeded" {
        sqlx::query_as::<_, (String,)>(
            "SELECT t.transaction_reference FROM transactions t \
             JOIN payments p ON p.id = t.payment_id \
             WHERE p.checkout_id = ? AND p.status = 'succeeded' \
             ORDER BY t.created_at DESC LIMIT 1",
        )
        .bind(&checkout.id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .map(|(r,)| r)
    } else {
        None
    };

    let error_message = params.get("error").map(|reason| error_text(reason, &amount_display));

    let step: u8 = if checkout.status == "succeeded" {
        3
    } else if checkout.status == "pending" && selected.is_some() && !wants_change {
        2
    } else {
        1
    };
    let show_instructions = checkout.status == "pending" && selected.is_some() && !show_methods;
    let show_change_method = show_instructions && !wants_change;

    let page = CheckoutPage {
        merchant_name,
        reference: checkout.reference.clone(),
        amount_display,
        checkout_id: checkout.id.clone(),
        csrf: csrf.clone(),
        step,
        show_methods,
        show_instructions,
        show_succeeded: checkout.status == "succeeded",
        show_expired: checkout.status == "expired",
        show_failed: checkout.status == "failed",
        show_change_method,
        items,
        has_items,
        slides,
        has_slides,
        methods,
        selected,
        error_message,
        paid_reference,
    };

    match page.render() {
        Ok(html) => {
            let response = Html(html).into_response();
            if set_cookie {
                set_cookie_on(response, format!("{CSRF_COOKIE}={csrf}; Path=/; HttpOnly; SameSite=Lax"))
            } else {
                response
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            simple_page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong. Please try again.")
        }
    }
}

#[derive(Deserialize)]
pub struct SelectMethodForm {
    pub csrf: String,
    pub method_id: String,
}

pub async fn select_method(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SelectMethodForm>,
) -> Response {
    if read_cookie(&headers, CSRF_COOKIE).as_deref() != Some(form.csrf.as_str()) {
        return simple_page(StatusCode::FORBIDDEN, "Your session expired. Go back and reload the page.");
    }

    let checkout = match domain::load_checkout(&state.pool, &checkout_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return simple_page(StatusCode::NOT_FOUND, "This checkout link does not exist."),
        Err(e) => return db_error_page(e),
    };
    if checkout.status != "created" && checkout.status != "pending" {
        return see_other(format!("/c/{checkout_id}"));
    }

    // Same method again is a no-op; otherwise the method must belong to this
    // merchant and be active.
    let method_ok = if checkout.selected_method_id.as_deref() == Some(form.method_id.as_str()) {
        true
    } else {
        matches!(
            domain::load_method(&state.pool, &form.method_id).await,
            Ok(Some(m)) if m.merchant_id == checkout.merchant_id && m.status == "active"
        )
    };
    if !method_ok {
        return see_other(format!("/c/{checkout_id}"));
    }

    if let Err(e) = sqlx::query(
        "UPDATE checkouts SET selected_method_id = ?, \
         status = CASE WHEN status = 'created' THEN 'pending' ELSE status END, updated_at = ? \
         WHERE id = ? AND status IN ('created', 'pending')",
    )
    .bind(&form.method_id)
    .bind(crate::ids::now_iso())
    .bind(&checkout_id)
    .execute(&state.pool)
    .await
    {
        return db_error_page(e);
    }

    tracing::info!(checkout_id = %checkout_id, method_id = %form.method_id, "payment method selected");
    see_other(format!("/c/{checkout_id}"))
}

#[derive(Deserialize)]
pub struct VerifyForm {
    pub csrf: String,
    pub transaction_reference: String,
}

pub async fn verify_form(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<VerifyForm>,
) -> Response {
    if read_cookie(&headers, CSRF_COOKIE).as_deref() != Some(form.csrf.as_str()) {
        return simple_page(StatusCode::FORBIDDEN, "Your session expired. Go back and reload the page.");
    }

    let return_url = match domain::load_checkout(&state.pool, &checkout_id).await {
        Ok(Some(c)) => c.return_url,
        Ok(None) => return simple_page(StatusCode::NOT_FOUND, "This checkout link does not exist."),
        Err(e) => return db_error_page(e),
    };

    let reference = form.transaction_reference.trim().to_string();
    if reference.is_empty() {
        return see_other(format!("/c/{checkout_id}?error=transaction_not_found"));
    }

    match domain::verify_checkout(&state, &checkout_id, &reference).await {
        Ok(VerifyResult::Succeeded { reference, .. }) => {
            redirect_after_success(&return_url, &checkout_id, &reference)
        }
        Ok(VerifyResult::Failed { reason, .. }) => see_other(format!("/c/{checkout_id}?error={reason}")),
        Ok(VerifyResult::AlreadyUsed) => see_other(format!("/c/{checkout_id}?error=transaction_already_used")),
        Ok(VerifyResult::NotPending { checkout_status }) => {
            if checkout_status == "succeeded" {
                see_other(format!("/c/{checkout_id}"))
            } else {
                see_other(format!("/c/{checkout_id}?error=checkout_not_pending"))
            }
        }
        Ok(VerifyResult::MethodNotSelected) => see_other(format!("/c/{checkout_id}")),
        Ok(VerifyResult::CheckoutNotFound) => {
            simple_page(StatusCode::NOT_FOUND, "This checkout link does not exist.")
        }
        Ok(VerifyResult::TooManyAttempts) => see_other(format!("/c/{checkout_id}?error=too_many_attempts")),
        Ok(VerifyResult::AttemptCooldown) => see_other(format!("/c/{checkout_id}?error=attempt_cooldown")),
        Ok(VerifyResult::ServiceUnavailable(_)) => {
            see_other(format!("/c/{checkout_id}?error=verification_service_unavailable"))
        }
        Err(e) => db_error_page(e),
    }
}

fn redirect_after_success(return_url: &Option<String>, checkout_id: &str, reference: &str) -> Response {
    if let Some(url) = return_url {
        if let Ok(mut parsed) = url::Url::parse(url) {
            {
                let mut pairs = parsed.query_pairs_mut();
                pairs.append_pair("checkoutId", checkout_id);
                pairs.append_pair("reference", reference);
                pairs.append_pair("status", "succeeded");
            }
            return Redirect::to(parsed.as_str()).into_response();
        }
    }
    see_other(format!("/c/{checkout_id}"))
}
