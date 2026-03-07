//! Local Authority (CA) management for DevCert.
//!
//! This module handles the creation and management of the local CA,
//! which is used to sign leaf certificates for development projects.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

/// Represents the local Certificate Authority (CA).
pub struct LocalAuthority {
    /// Path to the CA's private key file.
    pub key_path: PathBuf,
}

impl LocalAuthority {
    /// Generates a new local CA and saves it to the specified base directory.
    ///
    /// If the CA already exists, it will be reused instead of being regenerated.
    pub fn generate(dir: &Path) -> Result<Self> {
        // Create the directory if it doesn't exist
        Self::create_base_dir(&dir)?;

        // Define paths for the key and certificate
        let key_path = dir.join("localCA-key.pem");
        let cert_path = dir.join("localCA.pem");

        // Check if the key and certificate already exist
        if key_path.exists() && cert_path.exists() {
            println!("CA already exists. Skipping generation.");

            return Ok(Self { key_path });
        }

        // Generate a self-signed CA
        let key_pair = KeyPair::generate()?;
        let params = Self::build_params();
        let cert = params.self_signed(&key_pair)?;

        // Write the key and certificate to files
        Self::write_file(&key_path, &key_pair.serialize_pem().as_bytes(), 0o400)?;
        Self::write_file(&cert_path, &cert.pem().as_bytes(), 0o644)?;

        Ok(Self { key_path })
    }

    /// Signs a leaf certificate using the local CA.
    ///
    /// # Returns
    ///
    /// A tuple containing the generated key pair and the signed certificate.
    pub fn sign_leaf(&self, params: CertificateParams) -> Result<(KeyPair, Certificate)> {
        let key_pem = fs::read_to_string(&self.key_path)?;
        let cert_params = Self::build_params();

        let ca_key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::new(cert_params, ca_key_pair);

        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, &issuer)?;

        Ok((key_pair, cert))
    }

    /// Builds the certificate parameters for the local CA.
    fn build_params() -> CertificateParams {
        let mut params = CertificateParams::default();

        // Create a new distinguished name for the CA certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "DevCert");
        dn.push(DnType::CommonName, "DevCert Local CA");
        params.distinguished_name = dn;

        // Make this certificate a CA that can sign other certificates
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Specify the key usages
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Set the validity period for the CA
        let (not_before, not_after) = Self::validity_period();
        params.not_before = not_before;
        params.not_after = not_after;

        params
    }

    /// Defines the validity period for the CA certificate.
    fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
        let not_before = OffsetDateTime::now_utc()
            .checked_sub(Duration::days(1))
            .unwrap();

        let not_after = OffsetDateTime::now_utc()
            .checked_add(Duration::days(365 * 10))
            .unwrap();

        (not_before, not_after)
    }

    /// Writes content to a file at the specified path.
    fn write_file(path: &Path, content: &[u8], #[cfg(unix)] mode: u32) -> Result<()> {
        fs::write(path, content)?;

        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;

        Ok(())
    }

    /// Creates the base directory for storing CA files if it doesn't already exist.
    fn create_base_dir(path: &Path) -> Result<()> {
        fs::create_dir_all(path)?;

        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;

        Ok(())
    }
}
