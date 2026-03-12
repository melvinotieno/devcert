use time::{Duration, OffsetDateTime};

/// Returns a `(not_before, not_after)` validity window for a certificate.
///
/// `not_before` is the current time (UTC) and `not_after` is `days` days from now (UTC).
pub fn validity_period(days: i64) -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();

    let not_before = now;
    let not_after = now + Duration::days(days);

    (not_before, not_after)
}
