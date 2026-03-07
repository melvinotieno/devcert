use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::config::global::{CaRoot, GlobalConfig};
use crate::config::project::{CertConfig, ProjectConfig};
use crate::core::{ca::LocalAuthority, cert::LeafCert};

pub fn init_project() -> Result<()> {
    if ProjectConfig::exists() {
        anyhow::bail!("Project config already exists");
    }

    let cert_config = generate_project_config()?;

    let global_config = GlobalConfig::load()?;

    let base_path: PathBuf;

    if global_config.install.caroot == CaRoot::Global {
        base_path = GlobalConfig::get_base_path()?;
    } else {
        base_path = ProjectConfig::get_base_path()?;
    }

    let local_authority = LocalAuthority::generate(&base_path)?;

    let leaf_cert = LeafCert::from_config(&cert_config)?;

    leaf_cert.generate(&local_authority)?;

    Ok(())
}

/// Generates the project configuration and saves it.
fn generate_project_config() -> Result<CertConfig> {
    use crate::config::paths::DIR;

    let name = ProjectConfig::get_folder_name()?;
    let domains = prompt_domains()?;

    let cert_config = CertConfig {
        name,
        domains,
        key_path: DIR.to_string(),
        cert_path: DIR.to_string(),
    };

    let project_config = ProjectConfig {
        certs: vec![cert_config.clone()],
    };

    ProjectConfig::save(&project_config)?;

    Ok(cert_config)
}

/// Prompts the user to enter a list of domains for the certificate.
fn prompt_domains() -> Result<Vec<String>> {
    print!("Enter domains (comma-separated): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let domains: Vec<String> = input
        .split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(String::from)
        .collect();

    if domains.is_empty() {
        anyhow::bail!("{}", "At least one domain is required".red());
    }

    Ok(domains)
}
