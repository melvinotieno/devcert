//! Trust store management for DevCert.
//!
//! This module provides a unified [`TrustStore`] trait and platform-specific
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

use std::path::Path;

use anyhow::{Context, Result};

/// Operations common to all trust store backends.
pub trait TrustStore {
    /// Returns the human-readable name of this trust store backend.
    fn name(&self) -> &str {
        "System"
    }

    /// Returns `true` if the certificate identified by `id` is already trusted.
    fn check(&self, id: &str) -> bool;

    /// Installs the PEM/DER certificate at `cert_path` under the given `id`.
    fn install(&self, id: &str, cert_path: &Path) -> Result<()>;

    /// Removes the certificate identified by `id` from the store.
    fn uninstall(&self, id: &str) -> Result<()>;
}

/// Installs and removes certificates across a configured set of trust stores.
pub struct TrustStoreManager {
    backends: Vec<Box<dyn TrustStore>>,
}

impl TrustStoreManager {
    /// Constructs a manager from a list of store name strings.
    ///
    /// Recognised store names:
    ///
    /// | Name       | Backend                                                 |
    /// |------------|---------------------------------------------------------|
    /// | `"system"` | OS-native store (macOS keychain / Windows Root / Linux) |
    /// | `"nss"`    | NSS databases (Firefox, Chromium, Chrome, Brave)        |
    /// | `"java"`   | JRE/JDK `cacerts` keystore                              |
    ///
    /// An empty list enables all backends by default. Unrecognised names are
    /// ignored with a warning. Backends whose required tooling is absent at
    /// runtime are skipped with a warning rather than returning an error.
    pub fn new(stores: &[String]) -> Result<Self> {
        let mut backends: Vec<Box<dyn TrustStore>> = Vec::new();

        let all = stores.is_empty();
        let enabled = |name: &str| all || stores.iter().any(|s| s == name);

        // Log any unrecognized store names for debugging purposes
        stores
            .iter()
            .filter(|s| !matches!(s.as_str(), "system" | "nss" | "java"))
            .for_each(|name| crate::debug!("Unknown trust store specified: {:?}", name));

        if enabled("system") {
            Self::push_system_store(&mut backends)?;
        }

        if enabled("java") {
            if which::which("keytool").is_ok() {
                match java::JavaTrustStore::new() {
                    Ok(store) => backends.push(Box::new(store)),
                    Err(e) => crate::warn!("Warning: skipping Java trust store — {}", e),
                }
            } else {
                crate::report::warn("Warning: skipping Java trust store — `keytool` not found");
            }
        }

        if enabled("nss") {
            if which::which("certutil").is_ok() {
                match nss::NssTrustStore::new() {
                    Ok(store) => backends.push(Box::new(store)),
                    Err(e) => crate::warn!("Warning: skipping NSS trust store — {}", e),
                }
            } else {
                crate::report::warn(
                    "Warning: skipping NSS trust store — `certutil` not found (install nss-tools)",
                );
            }
        }

        Ok(Self { backends })
    }

    /// Returns the names of every active backend that already trusts the certificate.
    pub fn check(&self, id: &str) -> Vec<String> {
        self.backends
            .iter()
            .filter(|b| b.check(id))
            .map(|b| b.name().to_owned())
            .collect()
    }

    /// Installs the certificate at `cert_path` into every active backend under `id`.
    ///
    /// Returns the names of backends the certificate was successfully installed into.
    pub fn install(&self, id: &str, cert_path: &Path) -> Result<Vec<String>> {
        let mut installed = Vec::new();

        for backend in &self.backends {
            match backend.install(id, cert_path) {
                Ok(()) => installed.push(backend.name().to_owned()),
                Err(e) => crate::debug!(
                    "Failed to install certificate into '{}' store: {:?}",
                    backend.name(),
                    e
                ),
            }
        }

        Ok(installed)
    }

    /// Removes the certificate identified by `id` from every active backend.
    ///
    /// Returns the names of backends the certificate was successfully removed from.
    pub fn uninstall(&self, id: &str) -> Result<Vec<String>> {
        let mut uninstalled = Vec::new();

        for backend in &self.backends {
            match backend.uninstall(id) {
                Ok(()) => uninstalled.push(backend.name().to_owned()),
                Err(e) => crate::debug!(
                    "Failed to uninstall certificate from '{}' store: {:?}",
                    backend.name(),
                    e
                ),
            }
        }

        Ok(uninstalled)
    }

    /// Detect the current platform and push the appropriate system store backend.
    fn push_system_store(backends: &mut Vec<Box<dyn TrustStore>>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use linux::LinuxTrustStore;
            backends
                .push(Box::new(LinuxTrustStore::new().context(
                    "Failed to initialize the Linux system trust store",
                )?));
        }

        #[cfg(target_os = "macos")]
        {
            use macos::MacOsTrustStore;
            backends
                .push(Box::new(MacosTrustStore::new().context(
                    "Failed to initialize the MacOS keychain trust store",
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
