//! Adapter for the real verification service:
//!
//! ```text
//! POST {VERIFY_SERVICE_URL}/v1/transactions/verify
//! { "provider": "tele", "reference": "CHQ0FJ403O",
//!   "expected_amount_minor": 31200, "expected_currency": "ETB",
//!   "expected_recipient": "251911119144", "expected_created_at": "...Z" }
//! ```
//!
//! The service expands bare references to the provider URL itself and checks
//! the expected_* values against the provider's record; a 200 means it found
//! a transaction for these expectations. We re-validate defensively in
//! domain::verify_checkout regardless.

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

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
        let url = format!("{}/v1/transactions/verify", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "provider": provider_slug(q.provider),
            "reference": q.reference,
            "expected_amount_minor": q.expected_amount_minor,
            "expected_currency": q.expected_currency,
            "expected_recipient": q.expected_recipient,
            "expected_created_at": q.expected_created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });

        let mut request = self.http.post(&url).json(&body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| VerifyError::Unavailable(format!("verification service unreachable: {e}")))?;

        let status = response.status();
        // The response body is useful in error messages either way.
        let text = response
            .text()
            .await
            .map_err(|e| VerifyError::Unavailable(format!("verification service read failed: {e}")))?;

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(VerifyError::NotFound);
        }
        // The service validates the expected_* fields itself; a 400/422 means
        // "no transaction satisfies these expectations" — same customer
        // outcome as not-found, without charging the service-outage budget.
        if status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        {
            return Err(VerifyError::NotFound);
        }
        if !status.is_success() {
            return Err(VerifyError::Unavailable(format!(
                "verification service returned {status}: {text}"
            )));
        }

        let value: Value = serde_json::from_str(&text)
            .map_err(|e| VerifyError::Unavailable(format!("invalid verification response: {e}")))?;
        parse_service_response(&value, q.reference)
    }
}

/// Our canonical provider ids -> the verification service's slugs.
/// Unknown ids pass through unchanged.
fn provider_slug(provider: &str) -> &str {
    match provider {
        "telebirr" => "tele",
        "cbebirr" => "cbe",
        other => other,
    }
}

/// Tolerant response parser: accepts snake_case or camelCase field names and
/// amounts as minor-unit ints or decimal strings/numbers.
fn parse_service_response(
    value: &Value,
    fallback_reference: &str,
) -> Result<VerifiedTransaction, VerifyError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    struct ServiceTransaction {
        #[serde(default)]
        status: Option<String>,
        #[serde(default, alias = "reference", alias = "transactionReference")]
        transaction_reference: Option<String>,
        #[serde(default, alias = "amountMinor")]
        amount_minor: Option<i64>,
        #[serde(default, alias = "amount")]
        amount: Option<Value>,
        #[serde(default)]
        currency: Option<String>,
        #[serde(default)]
        recipient: Option<String>,
        #[serde(
            default,
            alias = "occurredAt",
            alias = "createdAt",
            alias = "created_at",
            alias = "timestamp"
        )]
        occurred_at: Option<String>,
    }

    let body: ServiceTransaction = serde_json::from_value(value.clone())
        .map_err(|e| VerifyError::Unavailable(format!("invalid verification response: {e}")))?;

    let amount_minor = if let Some(minor) = body.amount_minor {
        // Already minor units — use as-is.
        minor
    } else {
        let amount_value = body.amount.ok_or_else(|| {
            VerifyError::Unavailable("verification response missing amount".to_string())
        })?;
        if let Some(s) = amount_value.as_str() {
            decimal_to_minor(s)
        } else {
            amount_value
                .as_number()
                .ok_or("invalid amount")
                .and_then(number_to_minor)
        }
        .map_err(|e| {
            VerifyError::Unavailable(format!("invalid amount from verification service: {e}"))
        })?
    };

    let occurred_at = body
        .occurred_at
        .as_deref()
        .and_then(parse_iso)
        .ok_or_else(|| {
            VerifyError::Unavailable("invalid or missing occurred_at from verification service".into())
        })?;

    // A 200 from the verify endpoint means the service matched the
    // transaction against the expectations; treat it as settled unless the
    // service explicitly reports otherwise.
    let status = body.status.unwrap_or_else(|| "success".to_string());

    Ok(VerifiedTransaction {
        reference: body
            .transaction_reference
            .unwrap_or_else(|| fallback_reference.to_string()),
        status,
        amount_minor,
        currency: body.currency.unwrap_or_else(|| "ETB".to_string()),
        recipient: body.recipient.unwrap_or_default(),
        occurred_at,
        raw: value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn parse(value: Value) -> Result<VerifiedTransaction, VerifyError> {
        parse_service_response(&value, "CHQ0FJ403O")
    }

    #[test]
    fn parses_snake_case_minor_units() {
        let tx = parse(serde_json::json!({
            "status": "success",
            "transaction_reference": "CHQ0FJ403O",
            "amount_minor": 31200,
            "currency": "ETB",
            "recipient": "251911119144",
            "occurred_at": "2026-09-13T13:03:05Z"
        }))
        .unwrap();
        assert_eq!(tx.amount_minor, 31200);
        assert_eq!(tx.currency, "ETB");
        assert_eq!(tx.recipient, "251911119144");
        assert_eq!(tx.status, "success");
        assert_eq!(tx.occurred_at, chrono::Utc.with_ymd_and_hms(2026, 9, 13, 13, 3, 5).unwrap());
    }

    #[test]
    fn parses_camel_case_decimal_amount() {
        let tx = parse(serde_json::json!({
            "transactionReference": "CHQ0FJ403O",
            "amount": "312.00",
            "currency": "ETB",
            "recipient": "251911119144",
            "occurredAt": "2026-09-13T13:03:05Z"
        }))
        .unwrap();
        assert_eq!(tx.amount_minor, 31200);
        // 200 without an explicit status is treated as verified.
        assert_eq!(tx.status, "success");
        assert_eq!(tx.reference, "CHQ0FJ403O");
    }

    #[test]
    fn missing_amount_is_unavailable() {
        let err = parse(serde_json::json!({ "recipient": "251911119144" })).unwrap_err();
        assert!(matches!(err, VerifyError::Unavailable(_)));
    }
}
