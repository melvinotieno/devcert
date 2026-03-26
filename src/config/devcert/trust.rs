//! Trust-store configuration.
//!
//! # Supported trust stores
//!
//! | Variant | Platform | Backed by |
//! |---------|----------|-----------|
//! | [`TrustStore::System`] | macOS, Windows, Linux | OS certificate store |
//! | [`TrustStore::Java`] | Cross-platform | JVM `cacerts` KeyStore |
//! | [`TrustStore::NSS`] | Linux | Firefox / Chrome NSS database |

use serde::{Deserialize, Serialize};

/// Configuration controlling which trust stores the CA certificate is installed into.
///
/// # Example (TOML)
///
/// ```toml
/// [trust]
/// auto = true
/// stores = ["system", "nss"]
///
/// [trust.java]
/// home = "/usr/lib/jvm/java-21"
///
/// [trust.nss]
/// profile_dirs = ["/home/user/.mozilla/firefox/abc123.default"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustConfig {
    /// When `true`, trust stores are updated automatically on certificate generation.
    pub auto: bool,
    /// The list of trust stores the CA certificate should be installed into.
    pub stores: Vec<TrustStore>,
    /// Java-specific trust store options.
    ///
    /// Only relevant when [`TrustStore::Java`] is included in [`TrustConfig::stores`].
    pub java: JavaTrustConfig,
    /// NSS-specific trust store options.
    ///
    /// Only relevant when [`TrustStore::NSS`] is included in [`TrustConfig::stores`].
    pub nss: NssTrustConfig,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            auto: true,
            stores: vec![TrustStore::System, TrustStore::Java, TrustStore::Nss],
            java: JavaTrustConfig::default(),
            nss: NssTrustConfig::default(),
        }
    }
}

/// Java-specific trust store options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JavaTrustConfig {
    /// Overrides the `JAVA_HOME` directory used to locate the JVM's `cacerts` KeyStore.
    ///
    /// When `None`, devcert resolves `JAVA_HOME` from the environment.
    pub home: Option<String>,
}

/// NSS-specific trust store options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NssTrustConfig {
    /// Explicit list of NSS profile directories to install the certificate into.
    ///
    /// When empty, devcert auto-discovers profile directories for Firefox and Chromium-based browsers.
    pub profile_dirs: Vec<String>,
}

/// A trust store that devcert can install the CA certificate into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStore {
    /// The operating-system certificate store.
    ///
    /// - **macOS**: Keychain (`security add-trusted-cert`)
    /// - **Windows**: Certificate Store (`certutil`)
    /// - **Linux**: System CA bundle (e.g. `/etc/ca-certificates`)
    System,
    /// The Java KeyStore (`cacerts`) used by the JVM.
    ///
    /// Requires `keytool` to be available on `PATH`, or [`JavaTrustConfig::home`]
    /// to be set explicitly.
    Java,
    /// Mozilla's Network Security Services (NSS) shared trust database.
    ///
    /// Used by Firefox and Chromium-based browsers on Linux. Requires `certutil`
    /// (from `libnss3-tools`) to be available on `PATH`.
    Nss,
}
