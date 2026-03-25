use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};

pub struct LeafCert {
    name: String,
    domains: Vec<String>,
    key_path: PathBuf,
    cert_path: PathBuf,
}

impl LeafCert {
    pub fn new(name: String, domains: Vec<String>, key_path: String, cert_path: String) -> Self {
        let base = Self::current_dir();

        Self {
            name,
            domains,
            key_path: base.join(key_path).join("leafKey.pem"),
            cert_path: base.join(cert_path).join("leafCert.pem"),
        }
    }

    pub fn sign(&self, key_path: &PathBuf, cert_path: &PathBuf) -> Result<()> {
        let ca_key_pem = fs::read_to_string(key_path).context("Failed to read CA key")?;
        let ca_cert_pem = fs::read_to_string(cert_path).context("Failed to read CA certificate")?;

        let ca_key_pair = KeyPair::from_pem(&ca_key_pem).context("Failed to parse CA key")?;

        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair)
            .context("Failed to create issuer")?;

        let params = self.build_params();

        let key_pair = KeyPair::generate().context("Failed to generate leaf key pair")?;

        let cert = params
            .signed_by(&key_pair, &issuer)
            .context("Failed to sign leaf certificate")?;

        self.create_dir_all()?;

        let result: Result<()> = (|| {
            super::write_file(&self.key_path, key_pair.serialize_pem().as_bytes(), 0o400)
                .with_context(|| "Failed to write leaf key file")?;
            super::write_file(&self.cert_path, cert.pem().as_bytes(), 0o644)
                .with_context(|| "Failed to write leaf certificate file")?;
            Ok(())
        })();

        if result.is_err() {
            fs::remove_file(&self.key_path).ok();
            fs::remove_file(&self.cert_path).ok();
        }

        result
    }

    fn build_params(&self) -> CertificateParams {
        let mut params = CertificateParams::default();

        let common_name = format!("DevCert {} Leaf Cert", super::title_case(&self.name));

        // Set the distinguished name for the leaf certificate
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::OrganizationName, "DevCert");
        dn.push(rcgen::DnType::OrganizationalUnitName, "DevCert Leaf Cert");
        dn.push(rcgen::DnType::CommonName, common_name);
        params.distinguished_name = dn;

        params.subject_alt_names = self
            .domains
            .iter()
            .filter_map(|d| d.clone().try_into().ok())
            .map(SanType::DnsName)
            .collect();

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Set the validity period to 875 days (approximately 2 years and 5 months)
        let (not_before, not_after) = super::validity_period(875);
        params.not_before = not_before;
        params.not_after = not_after;

        params
    }

    fn create_dir_all(&self) -> Result<()> {
        if let Some(parent) = self.key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = self.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Gets the current working directory, or exits with an error if it cannot be determined.
    fn current_dir() -> PathBuf {
        env::current_dir().unwrap_or_else(|error| {
            crate::report::error("Failed to determine the current directory.");
            crate::debug!("Failed to determine the current directory: {}", error);
            std::process::exit(1);
        })
    }
}
