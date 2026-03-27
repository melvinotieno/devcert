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

impl super::TrustBackend for LinuxTrustStore {
    fn check(&self, id: &str) -> bool {
        self.cert_path(id).exists()
    }

    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        if self.check(id) {
            crate::debug!("Certificate {:?} already present, skipping install", id);
            return Ok(());
        }

        let cert_content = std::fs::read(cert_path)
            .with_context(|| format!("Could not read the certificate from {:?}", cert_path))?;

        if !self.sudo_write(&self.cert_path(id), &cert_content) {
            anyhow::bail!("Failed to install certificate in the linux trust store");
        }

        if !self.refresh_trust_store() {
            anyhow::bail!(
                "Failed to refresh the linux trust store after installation. Run manually with: sudo {}",
                self.distro.command.join(" ")
            );
        }

        Ok(())
    }

    fn uninstall(&self, id: &str) -> Result<()> {
        if !self.check(id) {
            crate::debug!("Certificate {:?} not present, skipping uninstall", id);
            return Ok(());
        }

        let path = self.cert_path(id);
        let path_str = path.to_string_lossy();

        if !self.sudo_run(&["rm", "-f", &path_str]) {
            anyhow::bail!("Failed to uninstall certificate from the linux trust store");
        }

        if !self.refresh_trust_store() {
            anyhow::bail!(
                "Failed to refresh the linux trust store after uninstallation. Run manually with: sudo {}",
                self.distro.command.join(" ")
            );
        }

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

    /// Constructs the expected certificate path using the given certificate ID.
    fn cert_path(&self, id: &str) -> PathBuf {
        Path::new(self.distro.cert_dir).join(format!("{}.{}", id, self.distro.cert_ext))
    }

    /// Runs the distribution's trust store refresh command.
    fn refresh_trust_store(&self) -> bool {
        if !self.sudo_run(self.distro.command) {
            crate::debug!("Failed to refresh the system trust store");
            return false;
        }
        true
    }

    /// Runs a command with `sudo`, returning `true` if it succeeds, `false` otherwise.
    fn sudo_run(&self, args: &[&str]) -> bool {
        let output = match Command::new("sudo").args(args).output() {
            Ok(o) => o,
            Err(e) => {
                crate::debug!("Failed to spawn: sudo {} — {}", args.join(" "), e);
                return false;
            }
        };

        if !output.status.success() {
            crate::debug!(
                "sudo {} failed (status {:?}):\n{}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return false;
        }

        true
    }

    /// Writes `content` to `dest` via `sudo tee`, avoiding a temp-file copy.
    fn sudo_write(&self, dest: &Path, content: &[u8]) -> bool {
        let mut child = match Command::new("sudo")
            .args(["tee", &dest.to_string_lossy()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                crate::debug!("Failed to spawn sudo tee: {}", e);
                return false;
            }
        };

        // Write the certificate content to the stdin of `sudo tee`.
        {
            let stdin = match child.stdin.as_mut() {
                Some(s) => s,
                None => {
                    crate::debug!("Failed to open stdin for sudo tee");
                    return false;
                }
            };

            if let Err(e) = stdin.write_all(content) {
                crate::debug!("Failed to write certificate content to sudo tee: {}", e);
                return false;
            }
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                crate::debug!("Failed while waiting for sudo tee to finish: {}", e);
                return false;
            }
        };

        if !output.status.success() {
            crate::debug!(
                "sudo tee failed (status {:?}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return false;
        }

        true
    }
}

/// A supported Linux distribution and its trust store conventions.
#[derive(Debug, Clone, Copy)]
struct Distro {
    /// Directory where trusted CA certificates are stored.
    cert_dir: &'static str,
    /// File extension expected by the distribution's trust store.
    cert_ext: &'static str,
    /// Command to refresh the system trust store after changes.
    command: &'static [&'static str],
}

impl Distro {
    /// Detects the current Linux distribution by probing well-known certificate directories.
    fn detect() -> Result<Self> {
        const DISTROS: &[Distro] = &[
            // Arch-based
            Distro {
                cert_dir: "/etc/ca-certificates/trust-source/anchors/",
                cert_ext: "crt",
                command: &["trust", "extract-compat"],
            },
            // Debian-based
            Distro {
                cert_dir: "/usr/local/share/ca-certificates/",
                cert_ext: "crt",
                command: &["update-ca-certificates"],
            },
            // Red Hat-based
            Distro {
                cert_dir: "/etc/pki/ca-trust/source/anchors/",
                cert_ext: "pem",
                command: &["update-ca-trust", "extract"],
            },
            // openSUSE-based
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
                    "Automatic trust store management is not yet supported on this Linux distribution"
                )
            })
    }
}
