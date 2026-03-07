//! Project configuration management for DevCert.
//!
//! This module handles loading and managing the project config file,
//! which contains user preferences that apply to the current project.

use std::{env, fs, path::PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::paths::{get_project_base_path, get_project_config_path};

/// Project configuration for DevCert.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Certificate configuration for the project.
    #[serde(rename = "cert")]
    pub certs: Vec<CertConfig>,
}

impl ProjectConfig {
    /// Checks if the project config file exists.
    pub fn exists() -> bool {
        get_project_config_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Returns the project base path for DevCert.
    pub fn get_base_path() -> Result<PathBuf> {
        get_project_base_path()
    }

    /// Gets the name of the current folder.
    pub fn get_folder_name() -> Result<String> {
        let current_dir = env::current_dir()?;

        let folder_name = current_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Could not determine current folder name"))?
            .to_string();

        Ok(folder_name)
    }

    /// Loads the project configuration from the file system.
    pub fn load() -> Result<Self> {
        let path = get_project_config_path()?;

        if !path.exists() {
            anyhow::bail!("Project config file not found: {:?}", path);
        }

        let content = fs::read_to_string(&path)?;
        let config: ProjectConfig = toml::from_str(&content)?;

        Ok(config)
    }

    /// Saves the project configuration to the file system.
    pub fn save(&self) -> Result<()> {
        let path = get_project_config_path()?;
        let content = toml::to_string_pretty(self)?;

        fs::write(&path, content)?;

        Ok(())
    }
}

/// Configuration for a single certificate in the project.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertConfig {
    /// References the name of certificate.
    pub name: String,
    /// List of domains for the certificate.
    pub domains: Vec<String>,
    /// Path to the private key file for this certificate.
    pub key_path: String,
    /// Path to the certificate file for this certificate.
    pub cert_path: String,
}
