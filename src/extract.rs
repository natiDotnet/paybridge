//! Extract the transaction reference from a pasted payment notification.
//! Customers paste the whole wallet SMS/notification into the reference field;
//! per-provider patterns find the reference. Extraction is best-effort —
//! whatever comes out is still verified by the service, so a wrong extraction
//! fails exactly like a wrong hand-typed reference would.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Same canonical-id -> service-slug mapping as the HTTP adapter. Unknown
/// providers get no extraction (input passes through).
fn slug(provider: &str) -> Option<&'static str> {
    match provider {
        "telebirr" => Some("tele"),
        "cbebirr" => Some("cbe"),
        "cbe" => Some("cbe"),
        "boa" => Some("boa"),
        "zemen" => Some("zemen"),
        "dashen" => Some("dashen"),
        "awash" => Some("awash"),
        _ => None,
    }
}

/// The providers' own share/receipt links embed the reference — the most
/// reliable signal when the notification contains one. Shapes follow the
/// service's PROVIDER_URL_TEMPLATES.
fn url_regex(slug: &str) -> Option<&'static Regex> {
    static RES: OnceLock<HashMap<&'static str, Regex>> = OnceLock::new();
    let map = RES.get_or_init(|| {
        [("tele", r"transactioninfo\.ethiotelecom\.et/receipt/([A-Z0-9]+)"),
         ("cbe", r"apps\.cbe\.com\.et(?::100)?/\?id=([A-Z0-9]+)"),
         ("dashen", r"receipt\.dashensuperapp\.com/receipt/([A-Z0-9]+)"),
         ("awash", r"awashpay\.awashbank\.com(?::8225)?/([A-Z0-9\-]+)"),
         ("boa", r"cs\.bankofabyssinia\.com/api/onlineSlip/getDetails/\?id=([A-Z0-9]+)"),
         ("zemen", r"share\.zemenbank\.com/rt/([A-Z0-9]+)/pdf")]
        .into_iter()
        .filter_map(|(k, p)| Regex::new(p).ok().map(|r| (k, r)))
        .collect()
    });
    map.get(slug)
}

/// Provider-agnostic "labeled" reference: `Transaction ID: CHQ0FJ403O`,
/// `Ref No: FT2521…`, `Receipt Number: 94497…` etc. Tried first — the label
/// pins the reference even when a generic pattern would match other tokens.
fn labeled_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)(?i:transaction\s*(?:id|ref(?:erence)?(?:\s*number)?)|receipt\s*(?:no\.?|number|id)?|ref(?:erence)?\s*(?:no\.?|number)?)\s*[:：#\-]?\s+([A-Z0-9\-][A-Z0-9\-]{6,29})\b",
        )
        .expect("labeled reference regex")
    })
}

fn provider_regex(slug: &str) -> Option<&'static Regex> {
    static RES: OnceLock<HashMap<&'static str, Regex>> = OnceLock::new();
    let map = RES.get_or_init(|| {
        [("tele", r"\b(?=[A-Z0-9]{10}\b)[A-Z0-9]*[A-Z][A-Z0-9]*\b"),
         ("cbe", r"\bFT[A-Z0-9]{13,18}\b"),
         ("boa", r"\bFT[A-Z0-9]{13,18}\b"),
         ("dashen", r"\b(?=[A-Z0-9]{14,22}\b)[A-Z0-9]*[A-Z][A-Z0-9]*\b"),
         ("awash", r"\b-?[A-Z0-9]{10,16}-[A-Z0-9]{4,10}\b"),
         ("zemen", r"\b\d{10,12}[A-Z]{2,6}\d{5,12}[A-Z0-9]{1,4}\b")]
        .into_iter()
        .filter_map(|(k, p)| Regex::new(p).ok().map(|r| (k, r)))
        .collect()
    });
    map.get(slug)
}

/// Reduce pasted text to the transaction reference. Order:
/// 1. a bare reference (already exactly the provider shape) passes through,
/// 2. the provider.s own share/receipt URL in the text (most reliable),
/// 3. a labeled reference anywhere in the text,
/// 4. the provider.s bare pattern applied to the whole text,
/// 5. otherwise the input is used as-is (it verifies or fails like before).
pub fn extract_reference(provider: &str, input: &str) -> String {
    // Cap pathological pastes before running patterns.
    let input = input.trim();
    let input: String = input.chars().take(2000).collect();
    if input.is_empty() {
        return input;
    }
    let Some(slug) = slug(provider) else {
        return input;
    };

    if let Some(re) = provider_regex(slug) {
        if let Some(m) = re.find(&input) {
            if m.as_str() == input {
                return input;
            }
        }
    }
            if let Some(re) = url_regex(slug) {
                if let Some(caps) = re.captures(&input) {
                    if let Some(m) = caps.get(1) {
                        return m.as_str().to_string();
                    }
                }
            }
    if let Some(caps) = labeled_regex().captures(&input) {
        if let Some(m) = caps.get(1) {
            return m.as_str().to_string();
        }
    }
    if let Some(re) = provider_regex(slug) {
        if let Some(m) = re.find(&input) {
            return m.as_str().to_string();
        }
    }
    input
}

#[cfg(test)]
mod tests {
    use super::extract_reference;

    #[test]
    fn bare_references_pass_through() {
        assert_eq!(extract_reference("telebirr", "CHQ0FJ403O"), "CHQ0FJ403O");
        assert_eq!(extract_reference("cbe", "FT25211G11JQ21827223"), "FT25211G11JQ21827223");
        assert_eq!(extract_reference("zemen", "94497018108ATWR2520600HM"), "94497018108ATWR2520600HM");
    }

    #[test]
    fn extracts_from_telebirr_sms() {
        let sms = "You have sent 312.00 ETB to JOHN SUPPLIERS on 13/09/2026 at 13:02. \
                   Transaction ID: CHQ0FJ403O. Your balance is 1,240.50 ETB.";
        assert_eq!(extract_reference("telebirr", sms), "CHQ0FJ403O");
    }

    #[test]
    fn extracts_from_cbe_sms() {
        let sms = "Dear customer, you have transferred ETB 312.00 to 1000123456789. \
                   Ref: FT25211G11JQ21827223. Thank you for banking with CBE.";
        assert_eq!(extract_reference("cbe", sms), "FT25211G11JQ21827223");
    }

    #[test]
    fn extracts_from_boa_sms() {
        let sms = "Transaction successful. Amount: 500.00 ETB. Trx: FT252113TRLT13487";
        assert_eq!(extract_reference("boa", sms), "FT252113TRLT13487");
    }

    #[test]
    fn extracts_from_zemen_notification() {
        let sms = "Transfer of 250.00 ETB successful. Receipt 94497018108ATWR2520600HM";
        assert_eq!(extract_reference("zemen", sms), "94497018108ATWR2520600HM");
    }

    #[test]
    fn extracts_from_dashen_notification() {
        let sms = "Payment of 100 ETB done. Receipt No: 387ETAP2522000WK";
        assert_eq!(extract_reference("dashen", sms), "387ETAP2522000WK");
    }

    #[test]
    fn extracts_from_awash_notification() {
        let sms = "Your transfer of 300 ETB was successful. Reference -E41AE0D86FFA-21XYYW";
        assert_eq!(extract_reference("awash", sms), "-E41AE0D86FFA-21XYYW");
    }

    #[test]
    fn labeled_wins_over_generic_tokens() {
        // The balance token must not win over the labeled reference.
        let sms = "Sent 50.00 ETB. Balance: 1234AB5678. Transaction ID: CHQ0FJ403O";
        assert_eq!(extract_reference("telebirr", sms), "CHQ0FJ403O");
    }

    #[test]
    fn extracts_reference_from_real_zemen_atm_sms() {
        // Real notification: the reference is embedded in the share link, and
        // the feedback link carries a shorter id that must NOT win.
        let sms = "Dear Customer, Birr 2000 ATM cash withdrawal has been made from A/c No. 119xxxxxxxx3018 on 2-Sep-2026 . The A/c Available Bal. is Birr 207473.78 and transaction ATM location is TELE MEDHANIALEM BC . To download your payment information click this link https://share.zemenbank.com/rt/20123018108ATCW2624500Y0/pdf Thank you for banking with Zemen Bank To help us serve you better, please share us your feedback: https://feedback.zemenbank.com?ref=108ATCW2624500Y0 Link your Fayda: https://fayda.zemenbank.com/ For any support, Please call 6500";
        assert_eq!(extract_reference("zemen", sms), "20123018108ATCW2624500Y0");
    }

    #[test]
    fn unmatched_text_passes_through() {
        let sms = "some completely unrelated paste";
        assert_eq!(extract_reference("telebirr", sms), sms);
    }

    #[test]
    fn legacy_provider_slugs_map() {
        assert_eq!(extract_reference("cbebirr", "Ref: FT25211G11JQ21827223"), "FT25211G11JQ21827223");
    }
}
