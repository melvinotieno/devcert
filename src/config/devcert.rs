mod ca;
mod registry;
mod trust;

use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub use ca::CaRoot;
pub use trust::TrustStore;

/// Top-level global configuration for DevCert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DevCert {
    /// CA configuration.
    pub ca: ca::CaConfig,
    /// Trust store configuration.
    pub trust: trust::TrustConfig,
}

impl Default for DevCert {
    fn default() -> Self {
        Self {
            ca: ca::CaConfig::default(),
            trust: trust::TrustConfig::default(),
        }
    }
}

impl DevCert {
    pub const DIR: &'static str = ".devcert";

    const CONFIG: &'static str = "config.toml";

    /// Returns `true` if the config file exists on disk.
    pub fn exists() -> bool {
        Self::config_path().exists()
    }

    /// Creates a new config with the specified CA root mode, without saving to disk.
    pub fn new(root: CaRoot, auto_trust: bool) -> Self {
        let mut ca_config = ca::CaConfig::default();
        let mut trust_config = trust::TrustConfig::default();

        ca_config.root = root;
        trust_config.auto = auto_trust;

        Self {
            ca: ca_config,
            trust: trust_config,
        }
    }

    /// Loads the config from disk, or returns a default config if no file exists.
    pub fn load() -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            super::create_dir_all(&Self::dir_path(), 0o700)?;
            return Self::default().save();
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read devcert config file at {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse devcert config file at {}", path.display()))
    }

    /// Saves the config to disk, creating the config directory if it does not exist.
    pub fn save(&self) -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            super::create_dir_all(&Self::dir_path(), 0o700)?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize devcert config")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file at {}", path.display()))?;

        Ok(self.clone())
    }

    /// Loads the DevCert CA registry from disk.
    pub fn registry() -> Result<registry::Registry> {
        registry::Registry::load()
    }

    /// Returns the full path to the config file (`<dir>/config.toml`).
    pub fn config_path() -> PathBuf {
        Self::dir_path().join(Self::CONFIG)
    }

    /// Returns the devcert config directory.
    ///
    /// Resolution order:
    /// 1. `DEVCERT_HOME` environment variable (if set and non-empty).
    /// 2. `~/.devcert` relative to the current user's home directory.
    ///
    /// If neither can be determined, prints an error and exits the program.
    pub fn dir_path() -> PathBuf {
        if let Ok(explicit) = env::var("DEVCERT_HOME") {
            return PathBuf::from(explicit);
        }

        if let Some(home) = env::home_dir() {
            return home.join(Self::DIR);
        }

        crate::report::error(
            "Failed to determine home directory for devcert config. Please set the DEVCERT_HOME environment variable to a valid directory path.",
        );

        std::process::exit(1);
    }
}
