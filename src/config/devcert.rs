//! Global configuration management for DevCert.
//!
//! This module handles loading and managing the global config file,
//! which contains user preferences that apply across all projects.

mod ca;
mod registry;
mod trust;

pub use ca::CaRoot;
pub use registry::CertificateAuthority;
pub use trust::TrustStore;

use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
        Self::config_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    /// Loads the configuration from disk.
    ///
    /// Returns the default configuration if the file does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The config directory cannot be determined (see [`DevCert::dir_path`]).
    /// - The file exists but cannot be read.
    /// - The file exists but contains invalid TOML or unrecognised fields.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file at {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file at {}", path.display()))
    }

    /// Serializes the configuration to disk.
    ///
    /// Creates the config directory and any missing parent directories if they
    /// do not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The config directory cannot be determined (see [`DevCert::dir_path`]).
    /// - The directory cannot be created.
    /// - The file cannot be written.
    pub fn save(&self) -> Result<Self> {
        let path = Self::config_path()?;

        crate::system::dir::create_dir_all(path.parent().unwrap_or_else(|| path.as_path()), 0o700)
            .with_context(|| format!("Failed to devcert config directory at {}", path.display()))?;

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file at {}", path.display()))?;

        Ok(self.clone())
    }

    /// Loads the CA registry from disk.
    ///
    /// Returns an error if the registry file exists but cannot be read or parsed.
    pub fn registry() -> Result<registry::Registry> {
        registry::Registry::load()
    }

    /// Returns the full path to the config file (`<dir>/config.toml`).
    pub fn config_path() -> Result<PathBuf> {
        Self::dir_path().map(|path| path.join(Self::CONFIG))
    }

    /// Returns the devcert config directory.
    ///
    /// Resolution order:
    /// 1. `DEVCERT_HOME` environment variable (if set and non-empty).
    /// 2. `~/.devcert` relative to the current user's home directory.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `DEVCERT_HOME` is set nor the home
    /// directory can be determined.
    pub fn dir_path() -> Result<PathBuf> {
        if let Ok(explicit) = env::var("DEVCERT_HOME") {
            return Ok(PathBuf::from(explicit));
        }

        if let Some(home) = env::home_dir() {
            return Ok(home.join(Self::DIR));
        }

        anyhow::bail!(
            "Could not determine home directory. \
            Set the DEVCERT_HOME environment variable to an explicit config path to continue."
        );
    }
}
