//! Checkout state transitions and the verification orchestration — the heart
//! of PayBridge (docs/DESIGN.md §6 and §8). A transaction becomes "consumed"
//! only after every validation passes, inside a single DB transaction
//! together with the state change and the outbox event.

use chrono::SecondsFormat;
use serde_json::json;
use sqlx::SqlitePool;

use crate::ids::{new_id, now_iso, parse_iso, to_iso};
use crate::money::format_minor;
use crate::state::AppState;
use crate::verify::{VerifiedTransaction, VerifyError, VerifyQuery};

#[derive(Debug, sqlx::FromRow)]
pub struct CheckoutRow {
    pub id: String,
    pub merchant_id: String,
    pub reference: String,
    pub amount_minor: i64,
    pub currency: String,
    pub status: String,
    pub selected_method_id: Option<String>,
    pub return_url: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MethodRow {
    pub id: String,
    pub merchant_id: String,
    pub provider: String,
    pub display_name: String,
    pub account_identifier: String,
    pub instructions: String,
    pub status: String,
}

pub async fn load_checkout(pool: &SqlitePool, checkout_id: &str) -> Result<Option<CheckoutRow>, sqlx::Error> {
    sqlx::query_as::<_, CheckoutRow>(
        "SELECT id, merchant_id, reference, amount_minor, currency, status, selected_method_id, return_url, created_at \
         FROM checkouts WHERE id = ?",
    )
    .bind(checkout_id)
    .fetch_optional(pool)
    .await
}

pub async fn load_method(pool: &SqlitePool, method_id: &str) -> Result<Option<MethodRow>, sqlx::Error> {
    sqlx::query_as::<_, MethodRow>(
        "SELECT id, merchant_id, provider, display_name, account_identifier, instructions, status \
         FROM merchant_payment_methods WHERE id = ?",
    )
    .bind(method_id)
    .fetch_optional(pool)
    .await
}

pub enum VerifyResult {
    Succeeded { occurred_at: String, reference: String },
    /// Verification ran but validation rejected the transaction; the checkout
    /// stays pending and the customer may retry with another reference.
    Failed { reason: &'static str, detail: Option<String> },
    /// A real transaction, but it already paid a different checkout.
    AlreadyUsed,
    NotPending { checkout_status: String },
    MethodNotSelected,
    CheckoutNotFound,
    TooManyAttempts,
    AttemptCooldown,
    ServiceUnavailable(String),
    /// The merchant has no verification credit left; buy credit to resume.
    InsufficientCredits,
}

/// Wallet identifiers are matched loosely on case/whitespace only.
fn normalize_account(s: &str) -> String {
    s.trim().to_lowercase()
}

pub async fn verify_checkout(
    state: &AppState,
    checkout_id: &str,
    raw_reference: &str,
) -> Result<VerifyResult, sqlx::Error> {
    let reference = raw_reference.trim();
    let Some(checkout) = load_checkout(&state.pool, checkout_id).await? else {
        return Ok(VerifyResult::CheckoutNotFound);
    };

    if checkout.status == "created" {
        return Ok(VerifyResult::MethodNotSelected);
    }
    if checkout.status != "pending" {
        return Ok(VerifyResult::NotPending { checkout_status: checkout.status.clone() });
    }
    let Some(method_id) = checkout.selected_method_id.clone() else {
        return Ok(VerifyResult::MethodNotSelected);
    };
    let Some(method) = load_method(&state.pool, &method_id).await? else {
        return Ok(VerifyResult::MethodNotSelected);
    };

    // Prepaid credits: every successful verification costs the merchant one
    // credit. Credit-purchase checkouts (paid to the platform merchant) are
    // exempt — they are how merchants top up in the first place.
    let is_credit_purchase = sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM credit_purchases WHERE checkout_id = ?",
    )
    .bind(&checkout.id)
    .fetch_one(&state.pool)
    .await?
        .0
        > 0;
    if !is_credit_purchase {
        let (balance,): (i64,) = sqlx::query_as(
            "SELECT credit_balance FROM merchants WHERE id = ?",
        )
        .bind(&checkout.merchant_id)
        .fetch_one(&state.pool)
        .await?;
        if balance < 1 {
            return Ok(VerifyResult::InsufficientCredits);
        }
    }

    // Rate limits: total *real* attempts per checkout (verification-service
    // outages are never charged against the customer) and a small cooldown.
    let (attempts,) = sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM payment_attempts \
         WHERE checkout_id = ? AND outcome != 'verification_service_error'",
    )
    .bind(&checkout.id)
    .fetch_one(&state.pool)
    .await?;
    if attempts >= state.config.verify_max_attempts {
        return Ok(VerifyResult::TooManyAttempts);
    }
    if let Some((last_at,)) = sqlx::query_as::<_, (String,)>(
        "SELECT created_at FROM payment_attempts WHERE checkout_id = ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&checkout.id)
    .fetch_optional(&state.pool)
    .await?
    {
        if let Some(last) = parse_iso(&last_at) {
            let elapsed = (chrono::Utc::now() - last).to_std().unwrap_or_default();
            if elapsed < state.config.verify_cooldown {
                return Ok(VerifyResult::AttemptCooldown);
            }
        }
    }

    // One payment row per verify run.
    let payment_id = new_id("pay");
    sqlx::query(
        "INSERT INTO payments (id, checkout_id, method_id, provider, status, amount_minor, currency, created_at) \
         VALUES (?, ?, ?, ?, 'initiated', ?, ?, ?)",
    )
    .bind(&payment_id)
    .bind(&checkout.id)
    .bind(&method.id)
    .bind(&method.provider)
    .bind(checkout.amount_minor)
    .bind(&checkout.currency)
    .bind(now_iso())
    .execute(&state.pool)
    .await?;

    let query = VerifyQuery {
        provider: &method.provider,
        reference,
        expected_amount_minor: checkout.amount_minor,
        expected_currency: &checkout.currency,
        expected_recipient: &method.account_identifier,
        expected_created_at: parse_iso(&checkout.created_at).unwrap_or(chrono::Utc::now()),
    };

    let (attempt_outcome, attempt_detail, result): (&'static str, Option<String>, VerifyResult) =
        match state.verifier.find(&query).await {
            Err(VerifyError::NotFound) => (
                "transaction_not_found",
                None,
                VerifyResult::Failed { reason: "transaction_not_found", detail: None },
            ),
            Err(VerifyError::Unavailable(e)) => (
                "verification_service_error",
                Some(e.clone()),
                VerifyResult::ServiceUnavailable(e),
            ),
            Ok(tx) => {
                if tx.status != "success" {
                    (
                        "transaction_not_successful",
                        Some(format!("transaction status: {}", tx.status)),
                        VerifyResult::Failed {
                            reason: "transaction_not_successful",
                            detail: None,
                        },
                    )
                } else if tx.amount_minor != checkout.amount_minor {
                    let detail = format!(
                        "expected {} {}, transaction is for {} {}",
                        format_minor(checkout.amount_minor),
                        checkout.currency,
                        format_minor(tx.amount_minor),
                        tx.currency
                    );
                    (
                        "amount_mismatch",
                        Some(detail.clone()),
                        VerifyResult::Failed { reason: "amount_mismatch", detail: Some(detail) },
                    )
                } else if !tx.currency.eq_ignore_ascii_case(&checkout.currency) {
                    (
                        "currency_mismatch",
                        None,
                        VerifyResult::Failed {
                            reason: "currency_mismatch",
                            detail: Some(format!("expected {}, transaction is {}", checkout.currency, tx.currency)),
                        },
                    )
                } else if normalize_account(&tx.recipient) != normalize_account(&method.account_identifier) {
                    (
                        "recipient_mismatch",
                        None,
                        VerifyResult::Failed { reason: "recipient_mismatch", detail: None },
                    )
                } else if let Some(created_at) = parse_iso(&checkout.created_at) {
                    // 2-minute tolerance absorbs clock skew between PayBridge
                    // and the verification service.
                    if tx.occurred_at < created_at - chrono::Duration::minutes(2) {
                        (
                            "transaction_too_old",
                            None,
                            VerifyResult::Failed { reason: "transaction_too_old", detail: None },
                        )
                    } else {
                        match consume_transaction(
                            state,
                            &checkout,
                            &method,
                            &payment_id,
                            &tx,
                            is_credit_purchase,
                        )
                        .await
                        {
                            Ok(occurred_at) => (
                                "succeeded",
                                None,
                                VerifyResult::Succeeded {
                                    occurred_at,
                                    reference: tx.reference.clone(),
                                },
                            ),
                            Err(ConsumeError::AlreadyUsed) => (
                                "transaction_already_used",
                                None,
                                VerifyResult::AlreadyUsed,
                            ),
                            Err(ConsumeError::NoCredits) => {
                                mark_payment_failed(&state.pool, &payment_id).await?;
                                // Raced to zero between the gate and the
                                // consume; report without an attempt record.
                                return Ok(VerifyResult::InsufficientCredits);
                            }
                            Err(ConsumeError::LostRace) => {
                                mark_payment_failed(&state.pool, &payment_id).await?;
                                let current = load_checkout(&state.pool, &checkout.id)
                                    .await?
                                    .map(|c| c.status)
                                    .unwrap_or_else(|| "unknown".into());
                                return Ok(VerifyResult::NotPending { checkout_status: current });
                            }
                            Err(ConsumeError::Db(e)) => return Err(e),
                        }
                    }
                } else {
                    // Unparsable created_at would be a data bug; fail safe by
                    // treating the transaction as too old.
                    (
                        "transaction_too_old",
                        None,
                        VerifyResult::Failed { reason: "transaction_too_old", detail: None },
                    )
                }
            }
        };

    sqlx::query(
        "INSERT INTO payment_attempts (id, checkout_id, transaction_reference, outcome, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(new_id("att"))
    .bind(&checkout.id)
    .bind(reference)
    .bind(attempt_outcome)
    .bind(&attempt_detail)
    .bind(now_iso())
    .execute(&state.pool)
    .await?;

    if attempt_outcome != "succeeded" {
        mark_payment_failed(&state.pool, &payment_id).await?;
    }

    Ok(result)
}

async fn mark_payment_failed(pool: &SqlitePool, payment_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE payments SET status = 'failed' WHERE id = ?")
        .bind(payment_id)
        .execute(pool)
        .await?;
    Ok(())
}

enum ConsumeError {
    AlreadyUsed,
    NoCredits,
    LostRace,
    Db(sqlx::Error),
}

/// Atomically: insert the consumed transaction (UNIQUE guard against reuse),
/// flip the checkout to `succeeded` (guarded so only one winner), close the
/// payment, enqueue the webhook event, and settle credits — merchants pay one
/// credit per successful verification, and credit-purchase checkouts top the
/// buyer up (and activate them) in the very same transaction. Anything
/// failing rolls back all of it.
async fn consume_transaction(
    state: &AppState,
    checkout: &CheckoutRow,
    method: &MethodRow,
    payment_id: &str,
    tx: &VerifiedTransaction,
    is_credit_purchase: bool,
) -> Result<String, ConsumeError> {
    let occurred_at = to_iso(tx.occurred_at);
    let event_id = new_id("evt");
    let payload = json!({
        "eventId": event_id,
        "event": "checkout.payment_succeeded",
        "checkoutId": checkout.id,
        "reference": checkout.reference,
        "amount": format_minor(checkout.amount_minor),
        "amountMinor": checkout.amount_minor,
        "currency": checkout.currency,
        "paymentMethod": method.provider,
        "transactionReference": tx.reference,
        "status": "succeeded",
        "occurredAt": occurred_at,
    })
    .to_string();

    let mut db = state.pool.begin().await.map_err(ConsumeError::Db)?;

    let insert = sqlx::query(
        "INSERT INTO transactions \
         (id, payment_id, provider, transaction_reference, amount_minor, currency, recipient, occurred_at, raw_response, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(new_id("txn"))
    .bind(payment_id)
    .bind(&method.provider)
    .bind(&tx.reference)
    .bind(tx.amount_minor)
    .bind(&tx.currency)
    .bind(&tx.recipient)
    .bind(&occurred_at)
    .bind(tx.raw.to_string())
    .bind(now_iso())
    .execute(&mut *db)
    .await;

    if let Err(e) = insert {
        if e.as_database_error().map(|d| d.is_unique_violation()).unwrap_or(false) {
            return Err(ConsumeError::AlreadyUsed); // db drops -> rollback
        }
        return Err(ConsumeError::Db(e));
    }

    let updated = sqlx::query(
        "UPDATE checkouts SET status = 'succeeded', paid_at = ?, updated_at = ? \
         WHERE id = ? AND status = 'pending'",
    )
    .bind(&occurred_at)
    .bind(now_iso())
    .bind(&checkout.id)
    .execute(&mut *db)
    .await
    .map_err(ConsumeError::Db)?;
    if updated.rows_affected() == 0 {
        return Err(ConsumeError::LostRace); // someone else transitioned the checkout
    }

    sqlx::query("UPDATE payments SET status = 'succeeded' WHERE id = ?")
        .bind(payment_id)
        .execute(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;

    sqlx::query(
        "INSERT INTO outbox_messages (id, event_type, aggregate_id, payload, status, attempts, next_attempt_at, created_at) \
         VALUES (?, 'checkout.payment_succeeded', ?, ?, 'pending', 0, ?, ?)",
    )
    .bind(&event_id)
    .bind(&checkout.id)
    .bind(&payload)
    .bind(now_iso())
    .bind(now_iso())
    .execute(&mut *db)
    .await
    .map_err(ConsumeError::Db)?;

    if is_credit_purchase {
        // The buyer paid the platform wallet: credit their account and
        // activate the merchant — atomically with the checkout success.
        let (buyer_id, credits): (String, i64) = sqlx::query_as(
            "SELECT merchant_id, credits FROM credit_purchases WHERE checkout_id = ?",
        )
        .bind(&checkout.id)
        .fetch_one(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;
        sqlx::query(
            "INSERT INTO credit_ledger (id, merchant_id, delta, reason, checkout_id, created_at) \
             VALUES (?, ?, ?, 'purchase', ?, ?)",
        )
        .bind(new_id("crl"))
        .bind(&buyer_id)
        .bind(credits)
        .bind(&checkout.id)
        .bind(now_iso())
        .execute(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;
        sqlx::query(
            "UPDATE merchants SET credit_balance = credit_balance + ?, onboarding_status = 'approved' \
             WHERE id = ?",
        )
        .bind(credits)
        .bind(&buyer_id)
        .execute(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;
    } else {
        // One credit per successful verification; the > 0 guard rolls the
        // whole transaction back if credits ran out under us.
        let charged = sqlx::query(
            "UPDATE merchants SET credit_balance = credit_balance - 1 \
             WHERE id = ? AND credit_balance > 0",
        )
        .bind(&checkout.merchant_id)
        .execute(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;
        if charged.rows_affected() == 0 {
            return Err(ConsumeError::NoCredits);
        }
        sqlx::query(
            "INSERT INTO credit_ledger (id, merchant_id, delta, reason, checkout_id, created_at) \
             VALUES (?, ?, -1, 'verification', ?, ?)",
        )
        .bind(new_id("crl"))
        .bind(&checkout.merchant_id)
        .bind(&checkout.id)
        .bind(now_iso())
        .execute(&mut *db)
        .await
        .map_err(ConsumeError::Db)?;
    }

    db.commit().await.map_err(ConsumeError::Db)?;

    tracing::info!(checkout_id = %checkout.id, event_id = %event_id, "checkout succeeded; webhook event queued");
    Ok(occurred_at)
}

/// Unused now but kept next to the state machine: explicit expiry transition.
#[allow(dead_code)]
pub fn is_terminal(status: &str) -> bool {
    status == "succeeded" || status == "failed" || status == "expired"
}

#[allow(dead_code)]
pub fn occurred_at_to_string(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}
