//! CA (Certificate Authority) configuration.
//!
//! # CA root modes
//!
//! DevCert supports two root modes, controlled by [`CaRoot`]:
//!
//! - [`CaRoot::Global`] — a single CA shared across all projects, stored in
//!   the devcert config directory (`DEVCERT_HOME` or `~/.devcert`). The CA
//!   only needs to be trusted once regardless of how many projects use devcert.
//! - [`CaRoot::Project`] — a dedicated CA per project, stored alongside the
//!   project. Provides stronger isolation between projects, but each project's
//!   CA must be trusted separately.

use serde::{Deserialize, Serialize};

/// Configuration controlling how the local CA certificate is generated and managed.
///
/// # Example (TOML)
///
/// ```toml
/// [ca]
/// root = "project"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaConfig {
    /// Whether to use a global or per-project CA root.
    ///
    /// Defaults to [`CaRoot::Global`].
    pub root: CaRoot,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            root: CaRoot::Global,
        }
    }
}

/// Controls where the CA certificate and private key are stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaRoot {
    /// A single CA shared across all projects, stored globally.
    Global,
    /// A dedicated CA per project, stored in the project directory.
    Project,
}
