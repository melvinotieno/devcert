//! Leaf certificate generation and management.
//!
//! This module handles the creation and management of the leaf certificate.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SanType,
};
use time::{Duration, OffsetDateTime};

use crate::{config::project::CertConfig, core::ca::LocalAuthority};

/// Represents a leaf certificate.
pub struct LeafCert {
    /// The common name for the certificate.
    pub name: String,
    /// The domains that the certificate should cover.
    pub domains: Vec<String>,
    /// Path to the certificate's private key file.
    pub key_path: PathBuf,
    /// Path to the certificate file.
    pub cert_path: PathBuf,
}

impl LeafCert {
    /// Generates a leaf certificate signed by the provided local CA.
    ///
    /// The certificate will be saved to the specified key and cert paths.
    pub fn generate(&self, local_authority: &LocalAuthority) -> Result<()> {
        // Sign the leaf certificate using the local CA
        let params = Self::build_params(&self);
        let (key_pair, cert) = local_authority.sign_leaf(params)?;

        // Ensure the directory for the key file exists
        if let Some(key_dir) = self.key_path.parent() {
            fs::create_dir_all(key_dir)?;
        }

        // Ensure the directory for the cert file exists
        if let Some(cert_dir) = self.cert_path.parent() {
            fs::create_dir_all(cert_dir)?;
        }

        // Write the key and certificate to files
        Self::write_file(&self.key_path, &key_pair.serialize_pem().as_bytes())?;
        Self::write_file(&self.cert_path, &cert.pem().as_bytes())?;

        Ok(())
    }

    /// Generates leaf certificate options from the provided config.
    pub fn from_config(config: &CertConfig) -> Result<Self> {
        let current_dir = env::current_dir()?;

        Ok(Self {
            name: config.name.clone(),
            domains: config.domains.clone(),
            key_path: current_dir
                .join(&config.key_path)
                .join(format!("{}-key.pem", config.name)),
            cert_path: current_dir
                .join(&config.cert_path)
                .join(format!("{}.pem", config.name)),
        })
    }

    /// Builds the certificate parameters for the leaf certificate.
    fn build_params(&self) -> CertificateParams {
        let mut params = CertificateParams::default();

        // Create a new distinguished name for the certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &self.name);
        params.distinguished_name = dn;

        // Set the subject alternative names (SANs) for the certificate
        params.subject_alt_names = self
            .domains
            .iter()
            .filter_map(|d| d.clone().try_into().ok())
            .map(SanType::DnsName)
            .collect();

        // This is an end-entity certificate, not a CA
        params.is_ca = IsCa::NoCa;

        // Specify the key usages
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        // Specify the extended key usages
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Set the validity period for the certificate
        let (not_before, not_after) = Self::validity_period();
        params.not_before = not_before;
        params.not_after = not_after;

        params
    }

    /// Defines the validity period for the leaf certificate.
    fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
        let not_before = OffsetDateTime::now_utc()
            .checked_sub(Duration::days(1))
            .unwrap();

        let not_after = OffsetDateTime::now_utc()
            .checked_add(Duration::days(397))
            .unwrap();

        (not_before, not_after)
    }

    /// Writes content to a file at the specified path.
    fn write_file(path: &Path, content: &[u8]) -> Result<()> {
        fs::write(path, content)?;

        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;

        Ok(())
    }
}
