//! Core certificate authority and certificate management logic.
//!
//! This module contains the foundational components for creating and managing
//! a local Certificate Authority (CA) and issuing development TLS certificates.

pub mod ca;
pub mod cert;
pub mod trust;

use std::{fs, path::Path};

use anyhow::Result;
use time::{Duration, OffsetDateTime};

/// Calculates a validity period starting from the current time and lasting for the specified number of days.
///
/// # Arguments
///
/// * `days` - The number of days the validity period should last.
///
/// # Returns
///
/// A tuple containing the `not_before` and `not_after` timestamps for the validity period.
///
/// # Example
///
/// ```no_run
/// let (not_before, not_after) = validity_period(365);
/// assert!(not_after > not_before);
/// ```
pub fn validity_period(days: i64) -> (OffsetDateTime, OffsetDateTime) {
    // Ensure the validity period is positive to avoid generating already-expired certificates.
    assert!(days > 0, "validity period must be positive");

    let now = OffsetDateTime::now_utc();
    let not_before = now;
    let not_after = now + Duration::days(days);

    (not_before, not_after)
}

/// Converts a string to title case, capitalizing the first letter of each word and separating them with spaces.
///
/// Words are split on spaces, underscores, and hyphens. Empty words are ignored.
///
/// # Arguments
///
/// * `s` - The input string to convert.
///
/// # Returns
///
/// A new string in title case.
///
/// # Example
///
/// ```no_run
/// # use devcert::core::title_case;
/// assert_eq!(title_case("hello_world"), "Hello World");
/// assert_eq!(title_case("foo-bar baz"), "Foo Bar Baz");
/// ```
pub fn title_case(s: &str) -> String {
    s.split(|c: char| [' ', '_', '-'].contains(&c))
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

/// Writes `content` to `path`, creating or truncating the file as needed.
///
/// # Arguments
///
/// * `path` - The path to write the file to.
/// * `content` - The raw bytes to write.
/// * `mode` - Unix permission bits (e.g. `0o600` for private keys, `0o644` for certificates). Ignored on non-Unix platforms.
///
/// # Errors
///
/// Returns an error if the file cannot be created, written to, or if the permissions cannot be set.
///
/// # Example
///
/// ```no_run
/// write_file(Path::new("/tmp/ca.key"), key_bytes, 0o600)?;
/// write_file(Path::new("/tmp/ca.crt"), cert_bytes, 0o644)?;
/// ```
#[cfg(unix)]
pub fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Apply permission atomically when creating the file to avoid
    // accessibility beyond their intended permissions, even briefly.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;

    file.write_all(content)?;

    // Ensure final permissions are exact (unmask may have altered them)
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;

    Ok(())
}

#[cfg(not(unix))]
pub fn write_file(path: &Path, content: &[u8], _mode: u32) -> Result<()> {
    fs::write(path, content)?;
    Ok(())
}
