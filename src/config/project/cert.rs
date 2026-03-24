//! Leaf certificate configuration for the project.
//!
//! This represents the configuration for a single leaf certificate in the project. A project
//! can have multiple leaf certificates (apps), each with its own set of domains and file paths.

use serde::{Deserialize, Serialize};

/// Configuration for a single leaf certificate in the project.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertConfig {
    /// References the name of a project app.
    pub name: String,
    /// Domains to include in the certificate's SAN.
    pub domains: Vec<String>,
    /// Path to the private key file for this certificate.
    pub key_path: String,
    /// Path to the certificate file for this certificate.
    pub cert_path: String,
}
