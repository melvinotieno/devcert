//! Registry of managed Certificate Authorities.
//!
//! This registry tracks all CAs that devcert has created, along with
//! metadata such as when they were created, when they expire, and which
//! trust stores they have been installed into.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::devcert::{ca::CaRoot, trust::TrustStore};

/// Persistent registry of Certificate Authorities managed by devcert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registry {
    /// List of all CAs created by devcert.
    authorities: Vec<CertificateAuthority>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            authorities: Vec::new(),
        }
    }
}

impl Registry {
    const FILENAME: &'static str = "registry.json";

    /// Loads the registry from disk.
    ///
    /// Returns the default (empty) registry if the file does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The devcert directory cannot be determined (see [`super::DevCert::dir_path`]).
    /// - The file exists but cannot be read.
    /// - The file exists but contains invalid JSON or unrecognised fields.
    pub fn load() -> Result<Self> {
        let path = Self::file_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read registry file at {}", path.display()))?;

        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse registry file at {}", path.display()))
    }

    /// Serializes the registry to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The devcert directory cannot be determined (see [`super::DevCert::dir_path`]).
    /// - The registry cannot be serialized to JSON.
    /// - The file cannot be written to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::file_path()?;

        crate::system::dir::create_dir_all(path.parent().unwrap_or_else(|| path.as_path()), 0o700)
            .with_context(|| format!("Failed to devcert config directory at {}", path.display()))?;

        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize registry for saving")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write registry file at {}", path.display()))
    }

    /// Returns a list of all registered CAs.
    pub fn list(&self) -> &[CertificateAuthority] {
        &self.authorities
    }

    /// Finds a CA by its unique identifier.
    pub fn find(&self, id: &str) -> Option<&CertificateAuthority> {
        self.authorities.iter().find(|e| e.id == id)
    }

    /// Adds a new CA to the registry, or updates an existing entry with the same ID.
    pub fn upsert(&mut self, ca: CertificateAuthority) {
        match self.authorities.iter_mut().find(|e| e.id == ca.id) {
            Some(existing) => *existing = ca,
            None => self.authorities.push(ca),
        }
    }

    /// Removes a CA from the registry by its unique identifier.
    pub fn remove(&mut self, id: &str) {
        self.authorities.retain(|ca| ca.id != id);
    }

    /// Returns the path to the registry file.
    fn file_path() -> Result<PathBuf> {
        super::DevCert::dir_path().map(|path| path.join(Self::FILENAME))
    }
}

/// A Certificate Authority entry stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateAuthority {
    /// Unique identifier for this CA.
    pub id: String,
    /// Human-friendly name for this CA.
    pub name: String,
    /// Whether this is a global or project-scoped CA.
    #[serde(rename = "type")]
    pub root: CaRoot,
    /// Path to the directory containing the CA certificate and key.
    pub path: PathBuf,
    /// When this CA was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When this CA certificate expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The trust stores this CA has been installed into.
    pub trusted_stores: Vec<TrustStore>,
}
