//! Java trust store implementation using the `keytool` command-line utility.
//!
//! This module discovers Java installations by checking the `JAVA_HOME` environment variable,
//! common installation paths, and the system `PATH`. It then interacts with the `cacerts`
//! keystore(s) using `keytool` to check for, install, and uninstall certificates.
//!
//! Note: Modifying the `cacerts` keystore typically requires administrative privileges, so
//! users may need to run DevCert with elevated permissions for these operations to succeed.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

impl super::TrustBackend for JavaTrustStore {
    /// Returns the name of the trust store.
    fn name(&self) -> &str {
        "Java"
    }

    /// Returns `true` if the certificate is present in **all** discovered `cacerts` keystores.
    fn check(&self, id: &str) -> bool {
        let alias = Self::alias(id);
        self.cacerts_paths
            .iter()
            .all(|p| Self::alias_exists_in(p, &alias))
    }

    /// Installs the certificate into every discovered `cacerts` keystore.
    ///
    /// Keystores that already contain the certificate are skipped.
    /// Failures across individual keystores are aggregated into a single error.
    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        let alias = Self::alias(id);
        let mut errors: Vec<String> = Vec::new();

        for cacerts in &self.cacerts_paths {
            if Self::alias_exists_in(cacerts, &alias) {
                continue;
            }

            if let Err(e) = Self::import_into(cacerts, cert_path, &alias) {
                errors.push(format!("{} — {:?}", e, cacerts));
            }
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to install certificate into {} Java keystore(s):\n{}",
                errors.len(),
                errors.join("\n")
            );
        }

        Ok(())
    }

    /// Removes the certificate from every `cacerts` keystore that contains it.
    fn uninstall(&self, id: &str) -> Result<()> {
        let alias = Self::alias(id);
        let mut errors: Vec<String> = Vec::new();

        for cacerts in &self.cacerts_paths {
            if !Self::alias_exists_in(cacerts, &alias) {
                continue;
            }

            if let Err(e) = Self::delete_from(cacerts, &alias) {
                errors.push(format!("{} — {:?}", e, cacerts));
            }
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to remove certificate from {} Java keystore(s):\n{}",
                errors.len(),
                errors.join("\n")
            );
        }

        Ok(())
    }
}

/// Trust store implementation for Java (`cacerts` keystore).
pub struct JavaTrustStore {
    cacerts_paths: Vec<PathBuf>,
}

const CACERTS_PASSWORD: &str = "changeit";

impl JavaTrustStore {
    /// Discovers Java installations and initializes the trust store handle.
    pub fn new() -> Result<Self> {
        let cacerts_paths = Self::discover_cacerts();

        if cacerts_paths.is_empty() {
            anyhow::bail!(
                "No Java installation found. Set JAVA_HOME or ensure `java` is on your PATH."
            );
        }

        Ok(Self { cacerts_paths })
    }

    /// Generates a consistent alias for the certificate based on its ID.
    fn alias(id: &str) -> String {
        format!("devcert-{}", id)
    }

    /// Discovers potential `cacerts` keystore paths by checking environment variables,
    /// common installation directories, and the system `PATH` for Java executables.
    fn discover_cacerts() -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();

        if let Ok(home) = std::env::var("JAVA_HOME") {
            roots.push(PathBuf::from(home));
        }

        for link in &[
            "/usr/lib/jvm/default",
            "/usr/lib/jvm/default-java",
            "/usr/lib/jvm/default-runtime",
        ] {
            let p = PathBuf::from(link);
            if p.exists() {
                roots.push(p);
            }
        }

        if let Some(java_bin) = Self::find_java_on_path() {
            if let Some(jre_root) = java_bin.parent().and_then(|p| p.parent()) {
                roots.push(jre_root.to_owned());
            }
        }

        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut result = Vec::new();

        for root in roots {
            for relative in &["lib/security/cacerts", "jre/lib/security/cacerts"] {
                let candidate = root.join(relative);
                if candidate.exists() {
                    let canonical = candidate
                        .canonicalize()
                        .unwrap_or_else(|_| candidate.clone());
                    if seen.insert(canonical) {
                        result.push(candidate);
                    }
                }
            }
        }

        result
    }

    /// Attempts to find the `java` executable on the system `PATH`.
    fn find_java_on_path() -> Option<PathBuf> {
        let tool = if cfg!(target_os = "windows") {
            "where"
        } else {
            "which"
        };

        let output = Command::new(tool)
            .arg("java")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let line = std::str::from_utf8(&output.stdout)
            .ok()?
            .lines()
            .next()?
            .trim()
            .to_owned();

        let path = PathBuf::from(&line);
        path.canonicalize().ok().or(Some(path))
    }

    /// Checks if the given alias exists in the specified `cacerts` keystore.
    fn alias_exists_in(cacerts: &Path, alias: &str) -> bool {
        Command::new("keytool")
            .args([
                "-list",
                "-alias",
                alias,
                "-keystore",
                &cacerts.to_string_lossy(),
                "-storepass",
                CACERTS_PASSWORD,
                "-noprompt",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Imports the certificate into the specified `cacerts` keystore with the given alias.
    fn import_into(cacerts: &Path, cert_path: &Path, alias: &str) -> Result<()> {
        let status = Command::new("keytool")
            .args([
                "-importcert",
                "-trustcacerts",
                "-alias",
                alias,
                "-keystore",
                &cacerts.to_string_lossy(),
                "-storepass",
                CACERTS_PASSWORD,
                "-file",
                &cert_path.to_string_lossy(),
                "-noprompt",
            ])
            .stdout(Stdio::null())
            .status()
            .context("Failed to run keytool -importcert — is Java installed?")?;

        if !status.success() {
            anyhow::bail!(
                "keytool -importcert failed for {:?} — do you have write permission?",
                cacerts
            );
        }

        Ok(())
    }

    /// Deletes the certificate with the given alias from the specified `cacerts` keystore.
    fn delete_from(cacerts: &Path, alias: &str) -> Result<()> {
        let status = Command::new("keytool")
            .args([
                "-delete",
                "-alias",
                alias,
                "-keystore",
                &cacerts.to_string_lossy(),
                "-storepass",
                CACERTS_PASSWORD,
                "-noprompt",
            ])
            .stdout(Stdio::null())
            .status()
            .context("Failed to run keytool -delete")?;

        if !status.success() {
            anyhow::bail!(
                "keytool -delete failed for {:?} — do you have write permission?",
                cacerts
            );
        }

        Ok(())
    }
}
