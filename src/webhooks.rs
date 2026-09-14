//! Webhook signing and the outbox dispatcher.
//! Events are enqueued transactionally when a checkout succeeds (domain.rs);
//! this worker delivers them asynchronously with exponential backoff.

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::db;
use crate::ids::{new_id, now_iso, to_iso};
use crate::state::AppState;

/// `X-PayBridge-Signature: sha256=hex(HMAC_SHA256(endpoint_secret, raw_body))`
pub fn sign_payload(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn last_error_text(status_code: Option<i64>, error: &Option<String>) -> String {
    error
        .clone()
        .unwrap_or_else(|| format!("http {}", status_code.unwrap_or(0)))
}

pub async fn deliver_due_events(state: &AppState) -> usize {
    let due = match db::query_as::<(String, String, String, i64)>(
        "SELECT id, aggregate_id, payload, attempts FROM outbox_messages \
         WHERE status = 'pending' AND next_attempt_at <= ? \
         ORDER BY next_attempt_at LIMIT 20",
    )
    .bind(now_iso())
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "outbox query failed");
            return 0;
        }
    };

    let mut processed = 0;
    for (outbox_id, checkout_id, payload, attempts) in due {
        let endpoint = db::query_as::<(String, String, String)>(
            "SELECT e.id, e.url, e.secret FROM webhook_endpoints e \
             JOIN checkouts c ON c.merchant_id = e.merchant_id \
             WHERE c.id = ? AND e.status = 'active' LIMIT 1",
        )
        .bind(&checkout_id)
        .fetch_optional(&state.pool)
        .await;

        let endpoint = match endpoint {
            Ok(found) => found,
            Err(e) => {
                tracing::error!(error = %e, event_id = %outbox_id, "endpoint lookup failed");
                continue;
            }
        };

        let Some((endpoint_id, url, secret)) = endpoint else {
            let _ = db::query(
                "UPDATE outbox_messages SET status = 'dead', last_error = 'no active webhook endpoint' WHERE id = ?",
            )
            .bind(&outbox_id)
            .execute(&state.pool)
            .await;
            tracing::warn!(event_id = %outbox_id, "no active webhook endpoint; event dead-lettered");
            continue;
        };

        let attempt_no = attempts + 1;
        let started = Instant::now();
        let response = state
            .http
            .post(&url)
            .timeout(Duration::from_secs(10))
            .header("content-type", "application/json")
            .header("x-paybridge-signature", sign_payload(&secret, payload.as_bytes()))
            .header("x-paybridge-event-id", &outbox_id)
            .header("x-paybridge-timestamp", chrono::Utc::now().timestamp().to_string())
            .body(payload.clone())
            .send()
            .await;
        let duration_ms = started.elapsed().as_millis() as i64;

        let (status_code, error) = match response {
            Ok(r) => (Some(r.status().as_u16() as i64), None),
            Err(e) => (None, Some(e.to_string())),
        };

        let _ = db::query(
            "INSERT INTO webhook_deliveries (id, outbox_id, endpoint_id, attempt_no, status_code, error, duration_ms, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new_id("whd"))
        .bind(&outbox_id)
        .bind(&endpoint_id)
        .bind(attempt_no)
        .bind(status_code)
        .bind(&error)
        .bind(duration_ms)
        .bind(now_iso())
        .execute(&state.pool)
        .await;

        let success = status_code.map(|c| (200..300).contains(&c)).unwrap_or(false);
        if success {
            let _ = db::query("UPDATE outbox_messages SET status = 'delivered', attempts = ?, last_error = NULL WHERE id = ?")
                .bind(attempt_no)
                .bind(&outbox_id)
                .execute(&state.pool)
                .await;
            tracing::info!(event_id = %outbox_id, url = %url, attempt = attempt_no, "webhook delivered");
        } else {
            // schedule[attempt_no] = delay before attempt attempt_no + 1
            // (schedule[0] = 0s is the immediate first attempt; the row was
            // already created with next_attempt_at = now).
            match state.config.webhook_schedule.get(attempt_no as usize).copied() {
                Some(delay) => {
                    let next = to_iso(
                        chrono::Utc::now()
                            + chrono::Duration::from_std(delay)
                                .unwrap_or_else(|_| chrono::Duration::seconds(30)),
                    );
                    let detail = last_error_text(status_code, &error);
                    let _ = db::query(
                        "UPDATE outbox_messages SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE id = ?",
                    )
                    .bind(attempt_no)
                    .bind(&next)
                    .bind(&detail)
                    .bind(&outbox_id)
                    .execute(&state.pool)
                    .await;
                    tracing::warn!(
                        event_id = %outbox_id, url = %url, attempt = attempt_no,
                        next_attempt = %next, "webhook delivery failed; retry scheduled"
                    );
                }
                None => {
                    let detail = last_error_text(status_code, &error);
                    let _ = db::query(
                        "UPDATE outbox_messages SET status = 'dead', attempts = ?, last_error = ? WHERE id = ?",
                    )
                    .bind(attempt_no)
                    .bind(&detail)
                    .bind(&outbox_id)
                    .execute(&state.pool)
                    .await;
                    tracing::error!(event_id = %outbox_id, "webhook dead-lettered after all retries");
                }
            }
        }
        processed += 1;
    }
    processed
}

#[cfg(test)]
mod tests {
    use super::sign_payload;

    #[test]
    fn signature_is_stable_hex() {
        let sig = sign_payload("secret", b"hello");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
        // Same input/secret -> same signature.
        assert_eq!(sig, sign_payload("secret", b"hello"));
        // Different secret -> different signature.
        assert_ne!(sig, sign_payload("other", b"hello"));
    }
}
