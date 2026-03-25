//! Windows-specific trust store management for DevCert.
//!
//! Installs certificates into the Windows "Root" certificate store
//! (Local Machine scope) using the built-in `certutil.exe` tool.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

const ROOT_STORE: &str = "Root";

impl super::TrustBackend for WindowsTrustStore {
    /// Checks if a certificate with the given ID is already trusted.
    fn check(&self, id: &str) -> bool {
        Command::new("certutil")
            .args(["-store", ROOT_STORE, &Self::friendly_name(id)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Installs the certificate at `cert_path` into the system trust store.
    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        if self.check(id) {
            return Ok(());
        }

        let cert_content = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read certificate from {:?}", cert_path))?;

        let staging = self.staging_path(id);

        fs::write(&staging, &cert_content)
            .with_context(|| format!("Failed to stage certificate to {:?}", staging))?;

        let result = self
            .run_certutil(&["-addstore", "-f", ROOT_STORE, &staging.to_string_lossy()])
            .context("Failed to add certificate to the Windows Root trust store");

        let _ = std::fs::remove_file(&staging);

        result
    }

    /// Removes the certificate with the given ID from the system store.
    fn uninstall(&self, id: &str) -> Result<()> {
        if !self.check(id) {
            return Ok(());
        }

        self.run_certutil(&["delstore", ROOT_STORE, &Self::friendly_name(id)])
            .context("Failed to remove certificate from the Windows Root trust store")
    }
}

/// Trust store implementation for Windows.
pub struct WindowsTrustStore {
    /// Temporary directory used to stage certificate files for `certutil`.
    staging_dir: PathBuf,
}

impl WindowsTrustStore {
    /// Initializes the Windows trust store, setting up any necessary state.
    pub fn new() -> Result<Self> {
        Ok(Self {
            staging_dir: std::env::temp_dir(),
        })
    }

    /// Returns the staging path for a certificate with the given ID.
    fn staging_path(&self, id: &str) -> PathBuf {
        self.staging_dir.join(format!("devcert-{}.cer", id))
    }

    /// The friendly name used to identify the cert inside the Windows store.
    fn friendly_name(id: &str) -> String {
        format!("devcert-{}", &id[..16])
    }

    /// Runs `certutil` with the given arguments, returning an error if it fails.
    fn run_certutil(&self, args: &[&str]) -> Result<()> {
        let status = Command::new("certutil")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .with_context(|| format!("Failed to run: certutil {}", args.join(" ")))?;

        if !status.success() {
            anyhow::bail!(
                "certutil failed (exit {:?}) — are you running as administrator?",
                status.code()
            );
        }

        Ok(())
    }
}
