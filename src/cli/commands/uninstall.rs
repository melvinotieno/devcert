use anyhow::Result;

use crate::config::devcert::DevCert;
use crate::core::trust::TrustManager;

pub fn uninstall() -> Result<()> {
    let devcert = DevCert::load()?;

    let trust_manager = TrustManager::new(&devcert.trust.stores)?;
    trust_manager.uninstall("global")?;

    Ok(())
}
