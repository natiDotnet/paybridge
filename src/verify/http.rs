//! Adapter for the real verification service
//! (docs/VERIFICATION_SERVICE_CONTRACT.md).

use std::time::Duration;

use serde::Deserialize;

use super::{VerifyError, VerifiedTransaction, VerifyQuery};
use crate::ids::parse_iso;
use crate::money::{decimal_to_minor, number_to_minor};

#[derive(Clone)]
pub struct HttpVerifier {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl HttpVerifier {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build http client");
        Self { http, base_url, api_key }
    }

    pub async fn find(&self, q: &VerifyQuery<'_>) -> Result<VerifiedTransaction, VerifyError> {
        let reference = percent_encoding::utf8_percent_encode(
            q.reference,
            percent_encoding::NON_ALPHANUMERIC,
        );
        let url = format!(
            "{}/providers/{}/transactions/{}",
            self.base_url.trim_end_matches('/'),
            q.provider,
            reference
        );

        let mut request = self.http.get(&url);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| VerifyError::Unavailable(format!("verification service unreachable: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VerifyError::NotFound);
        }
        if !response.status().is_success() {
            return Err(VerifyError::Unavailable(format!(
                "verification service returned {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ProviderTransaction {
            status: String,
            #[serde(default)]
            transaction_reference: Option<String>,
            /// String or number per the contract; strings are preferred.
            amount: serde_json::Value,
            currency: String,
            recipient: String,
            occurred_at: String,
        }

        let body: ProviderTransaction = response
            .json()
            .await
            .map_err(|e| VerifyError::Unavailable(format!("invalid verification response: {e}")))?;

        let amount_minor = if let Some(s) = body.amount.as_str() {
            decimal_to_minor(s)
        } else {
            body.amount.as_number().ok_or("invalid amount").and_then(number_to_minor)
        }
        .map_err(|e| VerifyError::Unavailable(format!("invalid amount from verification service: {e}")))?;

        let occurred_at = parse_iso(&body.occurred_at)
            .ok_or_else(|| VerifyError::Unavailable("invalid occurredAt from verification service".into()))?;

        Ok(VerifiedTransaction {
            reference: body.transaction_reference.unwrap_or_else(|| q.reference.to_string()),
            status: body.status,
            amount_minor,
            currency: body.currency,
            recipient: body.recipient,
            occurred_at,
            raw: serde_json::json!({ "source": "verification-service" }),
        })
    }
}
