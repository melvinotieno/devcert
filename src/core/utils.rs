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

/// Converts a `snake_case`, `kebab-case`, or space-separated string to Title Case.
///
/// # Examples
/// ```
/// # use devcert::core::utils::title_case;
/// assert_eq!(title_case("hello_world"), "Hello World");
/// assert_eq!(title_case("foo-bar baz"), "Foo Bar Baz");
/// ```
pub fn title_case(s: &str) -> String {
    s.split(|c: char| c == ' ' || c == '_' || c == '-')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
