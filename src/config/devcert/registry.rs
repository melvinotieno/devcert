//! Registry of managed Certificate Authorities.
//!
//! This registry tracks all CAs that devcert has created, along with
//! metadata such as when they were created, when they expire, and which
//! trust stores they have been installed into.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::devcert::CaRoot;

/// Persistent registry of Certificate Authorities managed by devcert.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registry {
    /// List of all CAs created by devcert.
    authorities: Vec<CertificateAuthority>,
}

impl Registry {
    const FILENAME: &'static str = "registry.json";

    /// Loads the registry from disk, or returns an empty registry if no file exists.
    pub fn load() -> Result<Self> {
        let path = Self::file_path();

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read registry file at {}", path.display()))?;

        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse registry file at {}", path.display()))
    }

    /// Saves the registry to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::file_path();

        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize registry for saving")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write registry file at {}", path.display()))
    }

    /// Adds a new CA entry to the registry.
    pub fn add(
        &mut self,
        id: String,
        root: CaRoot,
        path: PathBuf,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) {
        self.authorities.push(CertificateAuthority {
            id,
            root,
            path,
            created_at,
            expires_at,
            trusted_stores: Vec::new(),
        });
    }

    /// Returns the path to the registry file.
    fn file_path() -> PathBuf {
        super::DevCert::dir_path().join(Self::FILENAME)
    }
}

/// A Certificate Authority entry stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateAuthority {
    /// Unique identifier for this CA.
    pub id: String,
    /// Whether this is a global or project-scoped CA.
    #[serde(rename = "type")]
    pub root: super::ca::CaRoot,
    /// Path to the directory containing the CA certificate and key.
    pub path: PathBuf,
    /// When this CA was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When this CA certificate expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The trust stores this CA has been installed into.
    pub trusted_stores: Vec<super::trust::TrustStore>,
}
