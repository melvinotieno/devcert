//! Local Certificate Authority management for DevCert.
//!
//! This module handles the creation and management of the local CA,
//! which is used to sign leaf certificates for development projects.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem, prelude::X509Certificate};

/// Manages the creation and resolution of local certificate authorities (CAs) for DevCert.
pub struct LocalAuthority {
    /// The file path to the CA's private key.
    key_path: PathBuf,
    /// The file path to the CA's certificate.
    cert_path: PathBuf,
}

impl LocalAuthority {
    /// Creates a new `LocalAuthority` instance with the specified key and certificate paths.
    pub fn new(dir: &Path) -> Self {
        Self {
            key_path: dir.join("devcertCA.key"),
            cert_path: dir.join("devcertCA.crt"),
        }
    }

    /// Returns the file path to the CA's private key.
    pub fn key_path(&self) -> &PathBuf {
        &self.key_path
    }

    /// Returns the file path to the CA's certificate.
    pub fn cert_path(&self) -> &PathBuf {
        &self.cert_path
    }

    /// Checks if both the CA's private key and certificate files exist.
    pub fn exists(&self) -> bool {
        self.key_path.exists() && self.cert_path.exists()
    }

    /// Regenerates the CA certificate and private key, replacing any existing files.
    ///
    /// This is useful for resetting the CA if it becomes compromised or if the configuration changes.
    pub fn regenerate(&self, name: Option<String>) -> Result<CertificateParams> {
        // Remove existing CA files if they exist
        if self.key_path.exists() {
            std::fs::remove_file(&self.key_path).ok();
        }
        if self.cert_path.exists() {
            std::fs::remove_file(&self.cert_path).ok();
        }

        self.generate(name)
    }

    /// Generates a new CA certificate and private key, and saves them to the specified file paths.
    pub fn generate(&self, name: Option<String>) -> Result<CertificateParams> {
        let params = Self::build_params(name);

        let key_pair = KeyPair::generate().context("Failed to generate CA key")?;

        let cert = params
            .self_signed(&key_pair)
            .context("Failed to genereate CA certificate")?;

        // Attempt to write the CA key and certificate files, cleaning up any partial files on error
        let result: Result<()> = (|| {
            super::write_file(&self.key_path, key_pair.serialize_pem().as_bytes(), 0o400)
                .with_context(|| "Failed to write CA key")?;
            super::write_file(&self.cert_path, cert.pem().as_bytes(), 0o644)
                .with_context(|| "Failed to write CA certificate")?;
            Ok(())
        })();

        if result.is_err() {
            std::fs::remove_file(&self.key_path).ok();
            std::fs::remove_file(&self.cert_path).ok();
        }

        result?;

        Ok(params)
    }

    /// Validates the CA key and certificate, ensuring they are well-formed and consistent.
    pub fn validate(&self) -> Result<()> {
        // Ensure both files exist before attempting to parse them
        if !self.key_path.exists() {
            anyhow::bail!("CA key not found at {}", self.key_path.display());
        }
        if !self.cert_path.exists() {
            anyhow::bail!("CA certificate not found at {}", self.cert_path.display());
        }

        // Parse the certificate
        let der = Self::read_cert(&self.cert_path)?;
        let cert = Self::parse_cert(&der)?;

        // Validate the certificate's validity period
        let now = time::OffsetDateTime::now_utc();
        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();

        if now < not_before {
            anyhow::bail!("CA certificate is not yet valid (becomes valid: {not_before})");
        }
        if now > not_after {
            anyhow::bail!("CA certificate has expired (expired: {not_after})");
        }

        // Verify BasicConstraints marks this as a CA
        let basic_constraints = cert
            .basic_constraints()
            .context("Failed to read BasicConstraints extension")?
            .ok_or_else(|| {
                anyhow::anyhow!("CA certificate is missing BasicConstraints extension")
            })?;

        if !basic_constraints.value.ca {
            anyhow::bail!("Certificate is not marked as a CA (BasicConstraints CA:false)");
        }

        // Verify KeyCertSign and CrlSign is present in KeyUsage
        let key_usage = cert
            .key_usage()
            .context("Failed to read KeyUsage extension")?
            .ok_or_else(|| anyhow::anyhow!("CA certificate is missing KeyUsage extension"))?;

        if !key_usage.value.key_cert_sign() {
            anyhow::bail!("CA certificate is missing the KeyCertSign key usage");
        }
        if !key_usage.value.crl_sign() {
            anyhow::bail!("CA certificate is missing the CrlSign key usage");
        }

        // Verify the public key in the certificate matches the derived public key from the private key
        let key_pem = std::fs::read_to_string(&self.key_path).context("Failed to read CA key")?;
        let key_pair = KeyPair::from_pem(&key_pem).context("Failed to parse CA key")?;
        let cert_public_key = &cert.public_key().subject_public_key.data;
        let keypair_public_key = key_pair.public_key_raw();

        if *cert_public_key != keypair_public_key {
            anyhow::bail!("CA private key does not match the certificate's public key");
        }

        Ok(())
    }

    /// Builds [`CertificateParams`] for a self-signed CA certificate.
    fn build_params(name: Option<String>) -> CertificateParams {
        let mut params = CertificateParams::default();

        // Determine the common name for the CA certificate
        let common_name = match name {
            Some(n) => format!("DevCert {} CA", super::title_case(&n)),
            None => "DevCert Global CA".to_string(),
        };

        // Create a new distinguished name for the CA certificate
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::OrganizationName, "DevCert");
        dn.push(rcgen::DnType::OrganizationalUnitName, "DevCert CA");
        dn.push(rcgen::DnType::OrganizationalUnitName, common_name);
        params.distinguished_name = dn;

        // Make this certificate a CA that can sign other certificates
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Set the validity period for the CA certificate (10 years)
        let (not_before, not_after) = super::validity_period(365 * 10);
        params.not_before = not_before;
        params.not_after = not_after;

        params
    }

    /// Parses a DER-encoded certificate from a byte slice.
    fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>> {
        parse_x509_certificate(der)
            .map(|(_, cert)| cert)
            .map_err(|e| anyhow::anyhow!("Failed to parse CA certificate: {e}"))
    }

    /// Reads a PEM certificate file and decodes it to raw DER bytes.
    fn read_cert(cert_path: &Path) -> Result<Vec<u8>> {
        let cert_pem = std::fs::read_to_string(cert_path).context(format!(
            "Failed to read CA certificate from {}",
            cert_path.display()
        ))?;

        let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse CA certificate PEM: {e}"))?;

        Ok(pem.contents)
    }
}
