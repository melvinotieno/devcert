//! Trust store management for DevCert.
//!
//! This module provides a unified [`TrustBackend`] trait and platform-specific
//! implementations that install, verify, and remove development CA certificates
//! from every relevant certificate database on the current machine.
//!
//! # Platform backends
//!
//! | Module        | What it manages                                          |
//! |---------------|----------------------------------------------------------|
//! | [`linux`]     | System CA store (Arch, Debian, Red Hat, openSUSE)        |
//! | [`macos`]     | macOS System keychain (`security` CLI)                   |
//! | [`windows`]   | Windows Root certificate store (`certutil.exe`)          |
//! | [`java`]      | JRE/JDK `cacerts` keystore (`keytool`)                   |
//! | [`nss`]       | NSS databases for Firefox, Chrome, Chromium, Brave       |

mod java;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod nss;
#[cfg(target_os = "windows")]
mod windows;

use std::{path::Path, rc::Rc};

use anyhow::{Context, Result};

use crate::config::devcert::TrustStore;

/// Manages trust backends for DevCert, providing a unified interface to check,
/// install, and uninstall certificates across multiple platforms and trust stores.
pub struct TrustManager {
    /// All available trust backends, regardless of whether they're enabled or not.
    all: Vec<Rc<dyn TrustBackend>>,
    /// The subset of backends that are enabled for installation (based on config).
    enabled: Vec<Rc<dyn TrustBackend>>,
}

impl TrustManager {
    /// Initializes the trust manager by detecting available backends and filtering
    /// them based on the provided configuration.
    pub fn new(stores: &[TrustStore]) -> Result<Self> {
        let mut all: Vec<Rc<dyn TrustBackend>> = Vec::new();

        Self::push_system_store(&mut all)?;

        if which::which("keytool").is_ok() {
            match java::JavaTrustStore::new() {
                Ok(store) => all.push(Rc::new(store)),
                Err(e) => {
                    crate::report::warn("Warning: skipping Java trust store");
                    crate::debug!("Warning: skipping Java trust store — {}", e)
                }
            }
        } else {
            crate::report::warn("Warning: skipping Java trust store — `keytool` not found");
        }

        if which::which("certutil").is_ok() {
            match nss::NssTrustStore::new() {
                Ok(store) => all.push(Rc::new(store)),
                Err(e) => {
                    crate::report::warn("Warning: skipping NSS trust store");
                    crate::debug!("Warning: skipping NSS trust store — {}", e)
                }
            }
        } else {
            crate::report::warn(
                "Warning: skipping NSS trust store — `certutil` not found (install nss-tools)",
            );
        }

        let enabled = if stores.is_empty() {
            all.clone()
        } else {
            all.iter()
                .filter(|b| stores.iter().any(|s| s.matches_backend(b.as_ref())))
                .cloned()
                .collect()
        };

        Ok(Self { all, enabled })
    }

    /// Returns the names of every backend that already trusts the certificate.
    ///
    /// Always checks **all** backends regardless of which stores are enabled.
    // pub fn check(&self, id: &str) -> Vec<String> {
    //     self.all
    //         .iter()
    //         .filter(|b| b.check(id))
    //         .map(|b| b.name().to_owned())
    //         .collect()
    // }

    /// Returns `true` if the certificate is present in enabled backends.
    pub fn installed(&self, id: &str) -> bool {
        self.enabled.iter().all(|b| b.check(id))
    }

    /// Installs the certificate into enabled backends only.
    pub fn install(&self, id: &str, cert_path: &Path) -> Result<Vec<String>> {
        let mut installed = Vec::new();

        for backend in &self.enabled {
            match backend.install(id, cert_path) {
                Ok(()) => installed.push(backend.name().to_owned()),
                Err(e) => crate::report::error(&format!(
                    "Failed to install certificate in {} trust store: {}",
                    backend.name(),
                    e
                )),
            }
        }

        Ok(installed)
    }

    /// Uninstalls the certificate from **all** backends regardless of which stores are enabled.
    pub fn uninstall(&self, id: &str) -> Result<Vec<String>> {
        let mut uninstalled = Vec::new();

        for backend in &self.all {
            match backend.uninstall(id) {
                Ok(()) => uninstalled.push(backend.name().to_owned()),
                Err(e) => crate::report::error(&format!(
                    "Failed to uninstall certificate from {} trust store: {}",
                    backend.name(),
                    e
                )),
            }
        }

        Ok(uninstalled)
    }

    /// Pushes the appropriate system trust store backend for the current platform, if supported.
    fn push_system_store(backends: &mut Vec<Rc<dyn TrustBackend>>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use linux::LinuxTrustStore;
            backends
                .push(Rc::new(LinuxTrustStore::new().context(
                    "Failed to initialize the Linux system trust store",
                )?));
        }

        #[cfg(target_os = "macos")]
        {
            use macos::MacosTrustStore;
            backends
                .push(Box::new(MacosTrustStore::new().context(
                    "Failed to initialize the macOS keychain trust store",
                )?));
        }

        #[cfg(target_os = "windows")]
        {
            use windows::WindowsTrustStore;
            backends
                .push(Box::new(WindowsTrustStore::new().context(
                    "Failed to initialize the Windows root trust store",
                )?));
        }

        Ok(())
    }
}

trait TrustBackend {
    /// Returns a human-friendly name for this trust backend (e.g. "System", "Java", "NSS").
    fn name(&self) -> &str {
        "System"
    }

    /// Returns `true` if the certificate with the given ID is already trusted by this backend.
    fn check(&self, id: &str) -> bool;

    /// Installs the certificate with the given ID from the specified file path.
    fn install(&self, id: &str, cert_path: &Path) -> Result<()>;

    /// Uninstalls the certificate with the given ID from this backend.
    fn uninstall(&self, id: &str) -> Result<()>;
}

trait MatchesBackend {
    /// Returns `true` if this `TrustStore` corresponds to the given `TrustBackend`.
    fn matches_backend(&self, backend: &dyn TrustBackend) -> bool;
}

impl MatchesBackend for TrustStore {
    fn matches_backend(&self, backend: &dyn TrustBackend) -> bool {
        matches!(
            (self, backend.name()),
            (TrustStore::System, "System") | (TrustStore::Java, "Java") | (TrustStore::NSS, "NSS")
        )
    }
}
