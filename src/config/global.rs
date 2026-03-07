//! Global configuration management for DevCert.
//!
//! This module handles loading and managing the global config file,
//! which contains user preferences that apply across all projects.

use std::fs;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::paths::get_global_config_path;

/// Global configuration for DevCert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalConfig {
    /// Installation configuration.
    pub install: InstallConfig,
}

impl Default for GlobalConfig {
    /// Returns the default global configuration.
    fn default() -> Self {
        Self {
            install: InstallConfig::default(),
        }
    }
}

impl GlobalConfig {
    /// Loads the global configuration from the file system.
    ///
    /// If the config file does not exist, returns the default configuration.
    pub fn load() -> Result<Self> {
        let path = get_global_config_path()?;

        if !path.exists() {
            return Ok(GlobalConfig::default());
        }

        let content = fs::read_to_string(&path)?;
        let config: GlobalConfig = toml::from_str(&content)?;

        Ok(config)
    }
}

/// Specifies where the CA root should be stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CaRoot {
    /// Store the CA root in a global location.
    Global,
    /// Store the CA root in the project directory.
    Project,
}

/// Configuration options for installation behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InstallConfig {
    /// The location where CA certificates should be stored.
    ///
    /// See [`CaRoot`] for possible values.
    pub caroot: CaRoot,
}

impl Default for InstallConfig {
    /// Returns the default installation configuration.
    fn default() -> Self {
        Self {
            caroot: CaRoot::Global,
        }
    }
}
