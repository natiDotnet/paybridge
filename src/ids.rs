//! ID generation (prefixed ULIDs) and UTC timestamp helpers.
//! All stored timestamps are ISO-8601 with a `Z` offset so lexicographic
//! ordering matches chronological ordering.

use chrono::{DateTime, SecondsFormat, Utc};

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new())
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn to_iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}
