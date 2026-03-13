use std::{fs, path::Path};

use anyhow::Result;

/// Writes `content` to `path`, creating or truncating the file as needed.
///
/// # Arguments
///
/// * `path` - The path to write the file to.
/// * `content` - The raw bytes to write.
/// * `mode` - Unix permission bits (e.g. `0o600` for private keys, `0o644` for certificates).
///            Ignored on non-Unix platforms.
///
/// # Errors
///
/// Returns an error if the file cannot be created, written to, or if the
/// permissions cannot be set.
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

    // Apply permision atomically when creating the file to avoid
    // accessibility beyond their intended permissions, even briefly.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;

    file.write_all(content)?;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;

    Ok(())
}

#[cfg(not(unix))]
pub fn write_file(path: &Path, content: &[u8], _mode: u32) -> Result<()> {
    fs::write(path, content)?;
    Ok(())
}
