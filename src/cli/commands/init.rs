use std::path::PathBuf;

use anyhow::Result;
use inquire::{Text, required};

use crate::config::devcert::CaRoot;
use crate::config::devcert::DevCert;
use crate::config::project::Project;
use crate::core::ca::LocalAuthority;
use crate::core::cert::LeafCert;
use crate::core::trust::TrustManager;

pub fn init() -> Result<()> {
    if Project::exists() {
        crate::report::info("Project already initialized.");
        return Ok(());
    } else {
        crate::report::info("Initializing DevCert project...");
    }

    let devcert = DevCert::load()?;

    let (id, base_path, name) = resolve(&devcert);

    let ca = LocalAuthority::new(&base_path);

    if !ca.exists() {
        ca.generate(name)?;
    } else {
        ca.validate()?;
    }

    let trust_manager = TrustManager::new(&devcert.trust.stores)?;

    if !trust_manager.installed(&id) {
        trust_manager.install(&id, &ca.cert_path())?;
    }

    let sans = generate_project_config(Project::folder_name())?;

    let leaf = LeafCert::new(
        Project::folder_name(),
        sans,
        DevCert::DIR.to_string(),
        DevCert::DIR.to_string(),
    );

    leaf.sign(ca.key_path(), ca.cert_path())?;

    crate::report::success("Project initialized successfully.");

    Ok(())
}

fn generate_project_config(app: String) -> Result<Vec<String>> {
    let domains = prompt_domains()?;

    Project::add_app(
        app,
        domains.clone(),
        DevCert::DIR.to_string(),
        DevCert::DIR.to_string(),
    )?;

    Ok(domains)
}

fn prompt_domains() -> Result<Vec<String>> {
    let domains = Text::new("Enter the domains to include in the certificate (comma-separated):")
        .with_validator(required!("This field is required"))
        .prompt()?;

    let domains = domains
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(domains)
}

fn resolve(devcert: &DevCert) -> (String, PathBuf, Option<String>) {
    match devcert.ca.root {
        CaRoot::Global => {
            crate::report::debug("Using global CA root based on config");
            ("global".to_string(), DevCert::dir_path(), None)
        }
        CaRoot::Project => {
            crate::report::debug("Using project CA root based on config");
            (
                Project::derive_id(),
                Project::dir_path(),
                Some(Project::folder_name()),
            )
        }
    }
}
