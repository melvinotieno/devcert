use std::{fs, path::Path};

use anyhow::Result;

/// Creates a directory and all of its parent components if they are missing.
///
/// # Arguments
///
/// * `path` - The directory path to create.
/// * `mode` - The Unix permission bits to set on the resulting directory (e.g. `0o755`).
///             Only applies to the final directory, not any intermediate parents.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or if the permissions cannot be set.
///
/// # Example
///
/// ```rust
/// use std::path::Path;
///
/// create_dir_all(Path::new("/tmp/foo/bar"), 0o755)?;
/// ```
pub fn create_dir_all(path: &Path, #[cfg(unix)] mode: u32) -> Result<()> {
    fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }

    Ok(())
}
