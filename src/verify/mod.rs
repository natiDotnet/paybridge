//! Verification-service boundary. PayBridge never talks to wallets; it asks
//! the existing verification service (or the mock, in dev) for authoritative
//! transaction facts. See docs/VERIFICATION_SERVICE_CONTRACT.md.

mod http;
mod mock;

pub use http::HttpVerifier;
pub use mock::MockVerifier;

use chrono::{DateTime, Utc};

use crate::config::Config;

/// Everything the verifier needs. The HTTP adapter only uses `provider` and
/// `reference`; the mock uses the expected values to produce realistic
/// happy-path responses without a fixture database.
pub struct VerifyQuery<'a> {
    pub provider: &'a str,
    pub reference: &'a str,
    pub expected_amount_minor: i64,
    pub expected_currency: &'a str,
    pub expected_recipient: &'a str,
    /// Checkout creation time — the transaction must have occurred after it
    /// (the customer can only pay after the checkout exists).
    pub expected_created_at: chrono::DateTime<chrono::Utc>,
}

/// Authoritative transaction facts as returned by the verification service.
#[derive(Debug)]
pub struct VerifiedTransaction {
    /// The provider's canonical reference (may differ in case from user input).
    pub reference: String,
    /// "success" | "failed" | "pending"
    pub status: String,
    pub amount_minor: i64,
    pub currency: String,
    pub recipient: String,
    pub occurred_at: DateTime<Utc>,
    pub raw: serde_json::Value,
}

#[derive(Debug)]
pub enum VerifyError {
    /// No such transaction at the provider.
    NotFound,
    /// The verification service itself failed (network, 5xx, bad payload).
    /// Never counted against the customer's verify-attempt budget.
    Unavailable(String),
}

#[derive(Clone)]
pub enum Verifier {
    Mock(MockVerifier),
    Http(HttpVerifier),
}

impl Verifier {
    pub fn from_config(config: &Config) -> Self {
        match config.verifier {
            crate::config::VerifierKind::Http if config.verify_service_url.is_some() => {
                Self::Http(HttpVerifier::new(
                    config.verify_service_url.clone().unwrap(),
                    config.verify_service_api_key.clone(),
                ))
            }
            _ => Self::Mock(MockVerifier),
        }
    }

    pub async fn find(&self, query: &VerifyQuery<'_>) -> Result<VerifiedTransaction, VerifyError> {
        match self {
            Self::Mock(v) => v.find(query).await,
            Self::Http(v) => v.find(query).await,
        }
    }
}
