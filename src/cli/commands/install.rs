use std::path::Path;

use anyhow::Result;
use inquire::{Confirm, Select};

use crate::config::devcert::{CaRoot, CertificateAuthority, DevCert, TrustStore};
use crate::config::project::Project;
use crate::core::ca::LocalAuthority;
use crate::trust::TrustStoreManager;

pub fn install() -> Result<()> {
    crate::report::debug("Starting installation process...");

    let devcert = resolve_devcert()?;

    let (ca, ca_info) = resolve_ca(&CaRoot::Global)?;

    let trust_stores: Vec<String> = devcert.trust.stores.iter().map(|s| s.to_string()).collect();

    if devcert.trust.auto {
        trust_ca(&trust_stores, &ca_info.id, &ca.cert_path())?;
    }

    crate::report::success("Installation complete!");

    Ok(())
}

fn resolve_devcert() -> Result<DevCert> {
    if DevCert::exists() {
        match DevCert::load() {
            Ok(config) => Ok(config),
            Err(e) => {
                crate::debug!("{}", e);

                let answer = Confirm::new(
                    "Existing configuration is invalid. Do you want to overwrite it with defaults?",
                )
                .with_default(false)
                .prompt()?;

                match answer {
                    true => Ok(DevCert::default().save()?),
                    false => {
                        anyhow::bail!(
                            "Cannot proceed without a valid devcert config file. Please fix or remove the existing config at {:?} and try again.",
                            DevCert::config_path()?
                        );
                    }
                }
            }
        }
    } else {
        // --- CA scope ---
        let scope = Select::new(
            "Where should the Certificate Authority be scoped?",
            vec![CaRoot::Global, CaRoot::Project],
        )
        .with_help_message(
            "Global: one shared CA for all projects.\nProject: a CA tied to a project directory.",
        )
        .prompt()?;

        if matches!(scope, CaRoot::Project) {
            crate::report::info("Note: a global CA will still be generated.");
        }

        // --- Auto-trust ---
        let auto_trust = Confirm::new("Automatically install the CA into system trust stores?")
        .with_default(true)
        .with_help_message(
            "Installs the CA so browsers and other tools trust your local certificates without any manual steps.",
        )
        .prompt()?;

        let mut config = DevCert::default();
        config.ca.root = scope;
        config.trust.auto = auto_trust;

        config.save()
    }
}

fn resolve_ca(root: &CaRoot) -> Result<(LocalAuthority, CertificateAuthority)> {
    let (id, path, name) = match root {
        CaRoot::Global => ("global".to_string(), DevCert::dir_path()?, None),
        CaRoot::Project => (
            Project::derive_id()?,
            Project::dir_path()?,
            Some(Project::folder_name()?),
        ),
    };

    if LocalAuthority::exists(&path) {
        crate::report::info("Certificate authority already exists.");
    } else {
        let scope = match root {
            CaRoot::Global => "global",
            CaRoot::Project => "project",
        };

        crate::info!("Generating {} certificate authority...", scope);
    }

    let mut ca = LocalAuthority::resolve(&path, name.as_deref())?;

    if let Err(e) = ca.validate() {
        crate::debug!("{}", e);

        let action = Select::new(
            "The Certificate Authority is invalid. How would you like to proceed?",
            vec!["Regenerate", "Fix manually"],
        )
        .with_help_message(
            "Regenerate: replace the CA with a freshly generated one.\nFix manually: exit now and repair or remove the files yourself.",
        )
        .prompt()?;

        match action {
            "Regenerate" => {
                crate::report::info("Regenerating certificate authority...");
                ca = LocalAuthority::regenerate(&path, name.as_deref())?;
            }
            _ => {
                anyhow::bail!(
                    "Please fix or remove the Certificate Authority at {:?} and try again.",
                    path
                );
            }
        }
    }

    let mut registry = DevCert::registry()?;

    let existing_trusted = registry
        .find(&id)
        .map(|entry| entry.trusted_stores.clone())
        .unwrap_or_default();

    let ca_info = CertificateAuthority {
        id,
        name: ca.common_name().to_string(),
        root: root.clone(),
        path: path.to_path_buf(),
        created_at: ca.created_at(),
        expires_at: ca.expiry_date(),
        trusted_stores: existing_trusted,
    };

    registry.upsert(ca_info.clone());
    registry.save()?;

    Ok((ca, ca_info))
}

fn trust_ca(stores: &Vec<String>, id: &str, path: &Path) -> Result<Vec<TrustStore>> {
    let manager = TrustStoreManager::new(stores)?;

    let already_trusted = manager.check(id);

    if !already_trusted.is_empty() {
        crate::info!(
            "Certificate authority already trusted in: {}.",
            already_trusted.join(", ")
        );
    }

    let installed = manager.install(id, path)?;

    let trust_stores = installed
        .iter()
        .map(|s| s.to_lowercase().parse::<TrustStore>())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(trust_stores)
}
