use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::config::devcert::CaRoot;
use crate::config::devcert::DevCert;
use crate::config::project::Project;

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

/// Resolves and validates the home directory path for the given CA root.
///
/// # Arguments
/// * `root` - The CA root type (global or project) to determine which directory to resolve.
///
/// # Returns
/// * `Ok(PathBuf)` - The resolved directory path if it exists and is valid.
/// * `Err(DirError)` - An error indicating why the directory is missing or invalid
///
/// # Errors
/// * `DirError::Missing` - The directory does not exist and needs to be created
/// * `DirError::Invalid(String)` - The directory exists but is in an unexpected state
/// (e.g. it's a file instead of a directory, or there was an error accessing it)
///
/// # Example
/// ```rust
/// let dir = resolve_dir(&CaRoot::Global)?;
/// println!("Global CA home directory: {}", dir.display());
/// ```
pub fn resolve_dir(root: &CaRoot) -> Result<PathBuf, DirError> {
    let path = match root {
        CaRoot::Global => DevCert::dir_path(),
        CaRoot::Project => Project::dir_path(),
    }
    .map_err(|e| DirError::Invalid(e.to_string()))?;

    if !path.exists() {
        return Err(DirError::Missing);
    }

    if !path.is_dir() {
        return Err(DirError::Invalid(format!(
            "Expected a directory but found a file at {}",
            path.display()
        )));
    }

    Ok(path)
}

/// Represents the possible errors that can occur when resolving a directory path.
pub enum DirError {
    /// The path does not exist and needs to be created
    Missing,
    /// The path exists but is in an unexpected state
    Invalid(String),
}
