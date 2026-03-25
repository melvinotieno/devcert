use anyhow::Result;
use inquire::Select;

use crate::config::devcert::CaRoot;
use crate::config::devcert::DevCert;
use crate::core::ca::LocalAuthority;
use crate::core::trust::TrustManager;

pub fn install() -> Result<()> {
    global_install()
}

fn global_install() -> Result<()> {
    let devcert = if DevCert::exists() {
        crate::report::info("DevCert config already exists. Loading...");
        DevCert::load()?
    } else {
        let scope = prompt_scope()?;
        DevCert::new(scope, true).save()?
    };

    let mut registry = DevCert::registry()?;
    let ca = LocalAuthority::new(&DevCert::dir_path());
    let cert_id = "global".to_string();

    if ca.exists() {
        crate::report::info("CA already exists. Validating...");
        ca.validate()?;
    } else {
        crate::report::info("Generating local CA...");

        let params = ca.generate(None)?;

        registry.add(
            cert_id.clone(),
            CaRoot::Global,
            DevCert::dir_path(),
            params.not_before,
            params.not_after,
        );

        registry.save()?;
    }

    let trust_manager = TrustManager::new(&devcert.trust.stores)?;

    if trust_manager.installed(&cert_id) {
        crate::report::info("CA already installed in trust store.");
    } else {
        crate::report::info("Installing CA into trust store...");
        trust_manager.install(&cert_id, &ca.cert_path())?;
    }

    Ok(())
}

fn prompt_scope() -> Result<CaRoot> {
    let scope = Select::new("Where should the CA be scoped?", vec![CaRoot::Global, CaRoot::Project])
            .with_help_message("Global CAs can be used across multiple projects, while Project CAs are isolated to a single project directory.")
            .prompt()?;

    if matches!(scope, CaRoot::Project) {
        crate::report::info("Note: a global CA will still be generated.");
    }

    Ok(scope)
}
