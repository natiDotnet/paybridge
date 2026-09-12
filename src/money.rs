//! Money handling: everything is stored as INTEGER minor units (e.g. cents).
//! The API edge accepts JSON numbers (validated to <= 2 decimal places);
//! webhooks carry decimal strings plus `amountMinor` so no float ever crosses
//! a trust boundary.

/// Convert a JSON number to minor units. Rejects values with more than
/// 2 decimal places (float noise up to 1e-6 is tolerated for f64 inputs).
pub fn number_to_minor(n: &serde_json::Number) -> Result<i64, &'static str> {
    if let Some(i) = n.as_i64() {
        if i < 0 {
            return Err("invalid amount");
        }
        return i.checked_mul(100).ok_or("amount too large");
    }
    let f = n.as_f64().ok_or("invalid amount")?;
    if !f.is_finite() || f < 0.0 {
        return Err("invalid amount");
    }
    let scaled = f * 100.0;
    if (scaled - scaled.round()).abs() > 1e-6 {
        return Err("amount supports at most 2 decimal places");
    }
    let rounded = scaled.round();
    if rounded > 9.0e12 {
        return Err("amount too large");
    }
    Ok(rounded as i64)
}

/// Convert a decimal string (e.g. from the verification service) to minor units.
pub fn decimal_to_minor(s: &str) -> Result<i64, &'static str> {
    let s = s.trim();
    let (int_part, frac_part) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid amount");
    }
    if frac_part.len() > 2 || !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err("amount supports at most 2 decimal places");
    }
    let int: i64 = int_part.parse().map_err(|_| "amount too large")?;
    let frac: i64 = match frac_part.len() {
        0 => 0,
        1 => (frac_part.as_bytes()[0] - b'0') as i64 * 10,
        _ => {
            (frac_part.as_bytes()[0] - b'0') as i64 * 10
                + (frac_part.as_bytes()[1] - b'0') as i64
        }
    };
    int.checked_mul(100)
        .and_then(|hundreds| hundreds.checked_add(frac))
        .ok_or("amount too large")
}

/// Render minor units as a fixed 2-decimal string, e.g. 50000 -> "500.00".
pub fn format_minor(minor: i64) -> String {
    format!("{}.{:02}", minor / 100, minor % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_json_numbers() {
        assert_eq!(number_to_minor(&json!(500).as_number().unwrap()), Ok(50_000));
        assert_eq!(
            number_to_minor(&json!(500.5).as_number().unwrap()),
            Ok(50_050)
        );
        assert!(number_to_minor(&json!(0.005).as_number().unwrap()).is_err());
        assert!(number_to_minor(&json!(-1).as_number().unwrap()).is_err());
    }

    #[test]
    fn parses_decimal_strings() {
        assert_eq!(decimal_to_minor("500.00"), Ok(50_000));
        assert_eq!(decimal_to_minor("500.5"), Ok(50_050));
        assert_eq!(decimal_to_minor("500"), Ok(50_000));
        assert_eq!(decimal_to_minor(" 8.05 "), Ok(805));
        assert!(decimal_to_minor("1.234").is_err());
        assert!(decimal_to_minor("abc").is_err());
        assert!(decimal_to_minor("").is_err());
    }

    #[test]
    fn formats() {
        assert_eq!(format_minor(50_000), "500.00");
        assert_eq!(format_minor(805), "8.05");
        assert_eq!(format_minor(5), "0.05");
    }
}
