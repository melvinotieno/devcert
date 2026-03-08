//! Command for cleaning DevCert artifacts from the current project.
//!
//! This command removes the project's CA certificate from the system
//! trust store and deletes all generated certificate files.

use std::{env, fs};

use anyhow::Result;
use colored::Colorize;

use crate::config::manifest::Manifest;
use crate::config::project::ProjectConfig;
use crate::trust;

/// Cleans DevCert artifacts for the current project.
pub fn clean_project() -> Result<()> {
    let manifest = Manifest::load()?;
    let cert_path = ProjectConfig::get_base_path()?;
    let project_config = ProjectConfig::load()?;

    // Uninstall the project CA certificate if it is installed
    if trust::is_installed(&manifest.id, &cert_path)? {
        trust::uninstall(&manifest.id, &cert_path)?;
    }

    let current_dir = env::current_dir()?;

    // Remove the project's certificate and key files
    for cert in project_config.certs {
        let key_path = current_dir
            .join(cert.key_path)
            .join(format!("{}-key.pem", cert.name));

        let cert_path = current_dir
            .join(cert.cert_path)
            .join(format!("{}.pem", cert.name));

        fs::remove_file(key_path)?;
        fs::remove_file(cert_path)?;
    }

    // Delete the project's devcert directory
    std::fs::remove_dir_all(ProjectConfig::get_base_path()?)?;

    println!("{}", "Cleaned DevCert artifacts for the project.".green());

    Ok(())
}
