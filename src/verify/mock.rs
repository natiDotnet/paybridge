//! In-process mock of the verification service for local dev and tests.
//!
//! Reference prefixes (see docs/VERIFICATION_SERVICE_CONTRACT.md):
//! - anything else      -> success with the checkout's exact amount/recipient
//! - `mismatch-…`       -> success but a different amount   (amount_mismatch)
//! - `wrongwallet-…`    -> success but a different recipient (recipient_mismatch)
//! - `failed-…`         -> transaction exists, status failed
//! - `old-…`            -> success but 48h old             (transaction_too_old)
//! - `missing-…`        -> not found                       (transaction_not_found)

use chrono::{Duration, Utc};

use super::{VerifyError, VerifiedTransaction, VerifyQuery};

#[derive(Clone)]
pub struct MockVerifier;

impl MockVerifier {
    pub async fn find(&self, q: &VerifyQuery<'_>) -> Result<VerifiedTransaction, VerifyError> {
        let reference = q.reference.to_string();

        if reference.starts_with("missing-") {
            return Err(VerifyError::NotFound);
        }

        let (status, amount_minor, recipient) = if reference.starts_with("mismatch-") {
            ("success", q.expected_amount_minor - 100, q.expected_recipient.to_string())
        } else if reference.starts_with("wrongwallet-") {
            ("success", q.expected_amount_minor, "+251911111111".to_string())
        } else if reference.starts_with("failed-") {
            ("failed", q.expected_amount_minor, q.expected_recipient.to_string())
        } else {
            ("success", q.expected_amount_minor, q.expected_recipient.to_string())
        };

        let occurred_at = if reference.starts_with("old-") {
            q.expected_created_at - Duration::hours(48)
        } else {
            // Inside the payable window: after creation, at/just before now.
            q.expected_created_at + (Utc::now() - q.expected_created_at).min(Duration::minutes(4))
        };

        Ok(VerifiedTransaction {
            reference,
            status: status.to_string(),
            amount_minor,
            currency: q.expected_currency.to_string(),
            recipient,
            occurred_at,
            raw: serde_json::json!({ "source": "mock" }),
        })
    }
}
