//! Local Certificate Authority management for DevCert.
//!
//! This module handles the creation and management of the local CA,
//! which is used to sign leaf certificates for development projects.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use time::OffsetDateTime;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem, prelude::X509Certificate};

/// A local Certificate Authority backed by a key/certificate pair stored on disk.
#[derive(Debug, Clone)]
pub struct LocalAuthority {
    /// Path to the CA private key file.
    key_path: PathBuf,
    /// Path to the self-signed CA certificate file.
    cert_path: PathBuf,
    /// Common name for the CA certificate.
    common_name: String,
    /// Creation date of the CA certificate.
    created_at: OffsetDateTime,
    /// Expiry date of the CA certificate.
    expiry_date: OffsetDateTime,
}

impl LocalAuthority {
    const KEY_FILENAME: &'static str = "devcertCA-key.pem";
    const CERT_FILENAME: &'static str = "devcertCA.pem";

    /// Returns the path to the CA private key file.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Returns the path to the CA certificate file.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Returns the common name from the CA certificate's subject.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Returns the creation date of the CA certificate.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the expiry date of the CA certificate.
    pub fn expiry_date(&self) -> OffsetDateTime {
        self.expiry_date
    }

    /// Returns `true` if both the CA key and certificate files exist in `dir`.
    pub fn exists(dir: &Path) -> bool {
        let (key_path, cert_path) = Self::get_paths(dir);
        key_path.exists() && cert_path.exists()
    }

    /// Resolves the [`LocalAuthority`] in `dir`, generating a new CA if necessary.
    pub fn resolve(dir: &Path, name: Option<&str>) -> Result<Self> {
        let (key_path, cert_path) = Self::get_paths(dir);

        // Determine the common name for the CA certificate
        let common_name = match name {
            Some(n) => format!("DevCert {} CA", super::utils::title_case(n)),
            None => "DevCert Global CA".to_string(),
        };

        let (created_at, expiry_date) = if Self::exists(dir) {
            let der = Self::read_cert(&cert_path)?;
            let cert = Self::parse_cert(&der)?;

            (
                cert.validity().not_before.to_datetime(),
                cert.validity().not_after.to_datetime(),
            )
        } else {
            crate::system::dir::create_dir_all(dir, 0o700)
                .with_context(|| format!("Failed to create CA directory at {}", dir.display()))?;
            Self::generate(&key_path, &cert_path, &common_name)?
        };

        Ok(Self {
            key_path,
            cert_path,
            common_name,
            created_at,
            expiry_date,
        })
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
        let now = OffsetDateTime::now_utc();
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
        let key_pem = fs::read_to_string(&self.key_path).context("Failed to read CA key")?;
        let key_pair = KeyPair::from_pem(&key_pem).context("Failed to parse CA key")?;
        let cert_public_key = &cert.public_key().subject_public_key.data;
        let keypair_public_key = key_pair.public_key_raw();

        if *cert_public_key != keypair_public_key {
            anyhow::bail!("CA private key does not match the certificate's public key");
        }

        Ok(())
    }

    /// Generates a new CA key pair and self-signed certificate.
    fn generate(
        key_path: &Path,
        cert_path: &Path,
        common_name: &str,
    ) -> Result<(OffsetDateTime, OffsetDateTime)> {
        let key_pair = KeyPair::generate().context("Failed to generate CA key pair")?;

        let params = Self::build_params(common_name);

        // Generate a self-signed CA certificate using the parameters and key pair
        let cert = params
            .self_signed(&key_pair)
            .context("Failed to generate CA certificate")?;

        // Write the key and certificate to files
        let result: Result<()> = (|| {
            crate::system::file::write_file(key_path, key_pair.serialize_pem().as_bytes(), 0o400)
                .with_context(|| format!("Failed to write CA key to {key_path:?}"))?;
            crate::system::file::write_file(cert_path, cert.pem().as_bytes(), 0o644)
                .with_context(|| format!("Failed to write CA cert to {cert_path:?}"))?;
            Ok(())
        })();

        if result.is_err() {
            // Clean up any files that were created if writing failed
            let _ = fs::remove_file(key_path);
            let _ = fs::remove_file(cert_path);
        }

        result?;

        Ok((params.not_before, params.not_after))
    }

    /// Builds [`CertificateParams`] for a self-signed CA certificate.
    fn build_params(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::default();

        // Create a new distinguished name for the CA certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "DevCert");
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Make this certificate a CA that can sign other certificates
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Set the validity period for the CA
        let (not_before, not_after) = super::utils::validity_period(365 * 10);
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
        let cert_pem = fs::read_to_string(cert_path).context("Failed to read CA certificate")?;

        let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse CA certificate PEM: {e}"))?;

        Ok(pem.contents)
    }

    /// Returns the canonical `(key_path, cert_path)` pair for a given directory.
    fn get_paths(dir: &Path) -> (PathBuf, PathBuf) {
        let key_path = dir.join(Self::KEY_FILENAME);
        let cert_path = dir.join(Self::CERT_FILENAME);
        (key_path, cert_path)
    }
}
