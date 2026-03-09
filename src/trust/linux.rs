//! Linux-specific trust store management for DevCert.
//!
//! Supports Arch, Debian, Red Hat, and openSUSE-based distributions,
//! detected at runtime by probing well-known certificate directories.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

use crate::trust::TrustStore;

impl TrustStore for LinuxTrustStore {
    /// Checks if a certificate with the given ID is already trusted.
    fn check(&self, id: &str) -> bool {
        self.cert_path(id).exists()
    }

    /// Installs the certificate at `cert_path` into the system trust store.
    ///
    /// # Returns
    ///
    /// The derived ID of the installed certificate.
    fn install(&self, cert_path: &Path) -> Result<String> {
        let cert_content = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read certificate from {:?}", cert_path))?;

        let id = Self::derive_id(&cert_content);

        if self.check(&id) {
            return Ok(id);
        }

        self.sudo_write(&self.cert_path(&id), &cert_content)?;
        self.refresh_trust_store()?;

        Ok(id)
    }

    /// Removes the certificate with the given ID from the system store.
    fn uninstall(&self, id: &str) -> Result<()> {
        if !self.check(id) {
            return Ok(());
        }

        self.sudo_run(&["rm", "-f", &self.cert_path(id).to_string_lossy()])?;
        self.refresh_trust_store()?;

        Ok(())
    }
}

/// Trust store implementation for Linux.
pub struct LinuxTrustStore {
    /// Detected Linux distribution and its trust store conventions.
    distro: Distro,
}

impl LinuxTrustStore {
    /// Detects the Linux distribution and initializes the trust store.
    pub fn new() -> Result<Self> {
        Ok(Self {
            distro: Distro::detect()?,
        })
    }

    /// Constructs the full path for a certificate with the given ID.
    fn cert_path(&self, id: &str) -> PathBuf {
        Path::new(self.distro.cert_dir).join(format!("devcert-{}.{}", id, self.distro.cert_ext))
    }

    /// Derives a stable 64-char hex ID by SHA-256 hashing the certificate bytes.
    fn derive_id(cert_bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write;

        Sha256::digest(cert_bytes)
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                write!(s, "{:02x}", b).unwrap();
                s
            })
    }

    /// Runs the distribution's trust store refresh command.
    fn refresh_trust_store(&self) -> Result<()> {
        self.sudo_run(self.distro.command)
            .context("Failed to refresh the system trust store")
    }

    /// Runs a command under `sudo`, failing if it exits unsuccessfully.
    fn sudo_run(&self, args: &[&str]) -> Result<()> {
        let status = Command::new("sudo")
            .args(args)
            .status()
            .with_context(|| format!("Failed to run: sudo {}", args.join(" ")))?;

        if !status.success() {
            anyhow::bail!("Command failed: sudo {}", args.join(" "));
        }

        Ok(())
    }

    /// Writes `content` to `dest` via `sudo tee`, avoiding a temp-file copy.
    fn sudo_write(&self, dest: &Path, content: &[u8]) -> Result<()> {
        let mut child = Command::new("sudo")
            .args(["tee", &dest.to_string_lossy()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .context("Failed to spawn sudo tee — is sudo available?")?;

        child
            .stdin
            .take()
            .context("Could not open stdin for sudo tee")?
            .write_all(content)
            .context("Failed to pipe certificate content to sudo tee")?;

        let status = child.wait().context("sudo tee exited unexpectedly")?;

        if !status.success() {
            anyhow::bail!("sudo tee failed — do you have the required privileges?");
        }

        Ok(())
    }
}

/// A supported Linux distribution and its trust store conventions.
#[derive(Debug, Clone, Copy)]
struct Distro {
    /// Directory where CA certificates are installed.
    cert_dir: &'static str,
    /// File extension expected by the distribution's trust tooling.
    cert_ext: &'static str,
    /// Command to run after adding or removing a certificate.
    command: &'static [&'static str],
}

impl Distro {
    /// Probes well-known certificate directories to detect the Linux distribution.
    fn detect() -> Result<Self> {
        const DISTROS: &[Distro] = &[
            // Arch-based distros
            Distro {
                cert_dir: "/etc/ca-certificates/trust-source/anchors/",
                cert_ext: "crt",
                command: &["trust", "extract-compat"],
            },
            // Debian-based distros
            Distro {
                cert_dir: "/usr/local/share/ca-certificates/",
                cert_ext: "crt",
                command: &["update-ca-certificates"],
            },
            // Red Hat-based distros
            Distro {
                cert_dir: "/etc/pki/ca-trust/source/anchors/",
                cert_ext: "pem",
                command: &["update-ca-trust", "extract"],
            },
            // openSUSE-based distros
            Distro {
                cert_dir: "/usr/share/pki/trust/anchors/",
                cert_ext: "pem",
                command: &["update-ca-certificates"],
            },
        ];

        DISTROS
            .iter()
            .find(|d| Path::new(d.cert_dir).exists())
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Automatic trust store management is not supported on this Linux distribution"
                )
            })
    }
}
