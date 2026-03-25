//! macOS-specific trust store management for DevCert.
//!
//! Installs certificates into the System keychain using the `security`
//! command-line tool, which ships with every macOS installation.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

impl super::TrustBackend for MacosTrustStore {
    /// Checks if a certificate with the given ID is already trusted.
    fn check(&self, id: &str) -> bool {
        Command::new("security")
            .args([
                "find-certificate",
                "-c",
                &Self::cert_label(id),
                SYSTEM_KEYCHAIN,
            ])
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
            .run_security(&[
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                SYSTEM_KEYCHAIN,
                &staging.to_string_lossy(),
            ])
            .context("Failed to add certificate to the macOS System keychain");

        let _ = std::fs::remove_file(&staging);

        result
    }

    /// Removes the certificate with the given ID from the system store.
    fn uninstall(&self, id: &str) -> Result<()> {
        if !self.check(id) {
            return Ok(());
        }

        self.run_security(&[
            "delete-certificate",
            "-c",
            &Self::cert_label(id),
            SYSTEM_KEYCHAIN,
        ])
        .context("Failed to remove certificate from the macOS System keychain")
    }
}

/// Trust store implementation for macOS.
pub struct MacosTrustStore {
    /// Directory used to stage certificate files before adding to the keychain.
    staging_dir: PathBuf,
}

impl MacosTrustStore {
    /// Initializes the macOS trust store, setting up any necessary state.
    pub fn new() -> Result<Self> {
        Ok(Self {
            staging_dir: std::env::temp_dir(),
        })
    }

    /// Returns the label used to identify the certificate inside the keychain.
    fn cert_label(id: &str) -> String {
        format!("devcert-{}", id)
    }

    /// Returns the staging path for a certificate with the given ID.
    fn staging_path(&self, id: &str) -> PathBuf {
        self.staging_dir.join(format!("devcert-{}.pem", id))
    }

    /// Runs the `security` command with the given arguments, returning an error if it fails.
    fn run_security(&self, args: &[&str]) -> Result<()> {
        let status = Command::new("security")
            .args(args)
            .status()
            .with_context(|| format!("Failed to run: security {}", args.join(" ")))?;

        if !status.success() {
            anyhow::bail!("Command failed: security {}", args.join(" "));
        }

        Ok(())
    }
}
