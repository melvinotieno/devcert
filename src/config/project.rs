//! Project configuration management for DevCert.
//!
//! This module handles loading and managing the project config file,
//! which contains user preferences that apply to the current project.

mod cert;

use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Manages the project configuration for DevCert.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Certificates configuration for the project.
    #[serde(rename = "cert")]
    pub certs: Vec<cert::CertConfig>,
}

impl Project {
    const CONFIG: &'static str = ".devcert.toml";

    /// Returns `true` if a project configuration file exists in the current working directory.
    pub fn exists() -> bool {
        Self::config_path().exists()
    }

    /// Loads the project configuration from the current working directory, or returns a default config if no file exists.
    pub fn load() -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self { certs: Vec::new() });
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read project config file at {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse project config file at {}", path.display()))
    }

    /// Saves the project configuration to a file in the current working directory.
    pub fn save(&self) -> Result<Self> {
        let path = Self::config_path();

        let content = toml::to_string_pretty(self).context("Failed to serialize project config")?;

        fs::write(&path, content).with_context(|| {
            format!("Failed to write project config file at {}", path.display())
        })?;

        Ok(self.clone())
    }

    /// Derives a project ID from the current folder name.
    pub fn derive_id() -> String {
        let folder_name = Self::folder_name();

        let id = folder_name
            .chars()
            .map(|c| if c.is_whitespace() { '-' } else { c })
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>()
            .to_lowercase();

        if id.is_empty() {
            crate::report::error("Folder name contains no valid characters for a project ID.");
            std::process::exit(1);
        }

        id
    }

    /// Gets the name of the current project folder.
    pub fn folder_name() -> String {
        Self::current_dir()
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                crate::report::error("Failed to determine the project folder name.");
                std::process::exit(1);
            })
    }

    /// Gets the path to the project configuration file in the current working directory.
    pub fn config_path() -> PathBuf {
        Self::current_dir().join(Self::CONFIG)
    }

    /// Gets the path to the project directory, which is the current working directory.
    pub fn dir_path() -> PathBuf {
        Self::current_dir().join(super::devcert::DevCert::DIR)
    }

    /// Gets the current working directory, or exits with an error if it cannot be determined.
    fn current_dir() -> PathBuf {
        env::current_dir().unwrap_or_else(|error| {
            crate::report::error("Failed to determine the current directory.");
            crate::debug!("Failed to determine the current directory: {}", error);
            std::process::exit(1);
        })
    }
}
