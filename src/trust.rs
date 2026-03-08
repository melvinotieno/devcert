//! Platform-specific trust store management.
//!
//! This module provides an abstraction over the different
//! trust store implementation for each supported platform.

#[cfg(target_os = "linux")]
mod linux;

use std::path::PathBuf;

use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::trust::linux::LinuxTrustStore;

/// Describes the operations a platform trust store must support.
pub trait TrustStore {
    /// Returns `true` if the CA certificate is already trusted.
    fn check(&self) -> Result<bool>;

    /// Installs the CA certificate into the system trust store.
    fn install(&self) -> Result<()>;

    /// Removes the CA certificate from the system trust store.
    fn uninstall(&self) -> Result<()>;
}

/// Installs the CA certificate at `cert_path` into the system trust store.
pub fn install(name: &String, cert_path: &PathBuf) -> Result<()> {
    platform_store(name, cert_path).install()
}

/// Uninstalls the CA certificate from the system trust store.
pub fn uninstall(name: &String, cert_path: &PathBuf) -> Result<()> {
    platform_store(name, cert_path).uninstall()
}

/// Returns `true` if the CA certificate is already trusted by the system.
pub fn is_installed(name: &String, cert_path: &PathBuf) -> Result<bool> {
    platform_store(name, cert_path).check()
}

/// Constructs the correct trust store implementation for the current platform.
fn platform_store(name: &String, cert_path: &PathBuf) -> Box<dyn TrustStore> {
    #[cfg(target_os = "linux")]
    return Box::new(LinuxTrustStore::new(name, cert_path));
}
