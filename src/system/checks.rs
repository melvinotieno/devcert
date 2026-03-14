use std::path::PathBuf;

use crate::config::devcert::CaRoot;
use crate::config::devcert::DevCert;
use crate::config::project::Project;
use crate::core::ca::LocalAuthority;
use crate::trust::TrustStoreManager;

use super::Component;

/// Checks configuration validity based on the CA root scope.
/// - `Global` root: validates the DevCert config file.
/// - `Project` root: validates the project config file.
pub fn check_config(root: &CaRoot, devcert: Result<&DevCert, &str>) -> Component {
    match root {
        CaRoot::Global => check_devcert_config(devcert),
        CaRoot::Project => check_project_config(),
    }
}

/// Checks whether the local Certificate Authority exists and is valid.
///
/// Returns `Missing` if no CA is found, `Invalid` if it exists but fails to
/// load or validate, and `Ok` if it's healthy.
pub fn check_ca(path: &PathBuf) -> Component {
    if !LocalAuthority::exists(path) {
        return Component::Missing;
    }

    let ca = match LocalAuthority::resolve(path, None) {
        Ok(ca) => ca,
        Err(e) => {
            crate::debug!("Failed to resolve local CA: {}", e);
            return Component::Invalid {
                reason: "Failed to resolve local CA".to_string(),
            };
        }
    };

    if let Err(e) = ca.validate() {
        crate::debug!("Local CA validation failed: {}", e);
        return Component::Invalid {
            reason: "Local CA validation failed".to_string(),
        };
    }

    Component::Ok
}

/// Checks whether the CA certificate is trusted in the system's trust stores.
///
/// Skipped if:
/// - The DevCert config cannot be loaded.
/// - Auto-trust is disabled in the config.
///
/// Returns `Missing` if the cert is not yet trusted, `Invalid` if the trust
/// store manager fails to initialize, and `Ok` if the cert is trusted.
pub fn check_trust(root: &CaRoot, devcert: Result<&DevCert, &str>) -> Component {
    let Ok(config) = devcert else {
        crate::debug!(
            "DevCert config could not be loaded: {}",
            devcert.err().unwrap()
        );

        return Component::Skipped {
            because: "DevCert config could not be loaded",
        };
    };

    if !config.trust.auto {
        crate::report::debug("Auto-trust is disabled in the DevCert config");
        return Component::Skipped {
            because: "Auto-trust is disabled in the DevCert config",
        };
    }

    let stores: Vec<String> = config.trust.stores.iter().map(|s| s.to_string()).collect();

    let manager = match TrustStoreManager::new(&stores) {
        Ok(manager) => manager,
        Err(e) => {
            crate::debug!("Failed to initialize trust store manager: {}", e);
            return Component::Invalid {
                reason: "Failed to initialize trust store manager".to_string(),
            };
        }
    };

    // Use "global" as the trust ID for global roots; derive a unique ID for project roots.
    let id = match root {
        CaRoot::Global => "global".to_string(),
        CaRoot::Project => Project::derive_id(),
    };

    if !manager.check(&id) {
        return Component::Missing;
    }

    Component::Ok
}

/// Checks whether the DevCert config file exists and can be parsed.
fn check_devcert_config(devcert: Result<&DevCert, &str>) -> Component {
    if !DevCert::exists() {
        return Component::Missing;
    }

    match devcert {
        Ok(_) => Component::Ok,
        Err(e) => {
            crate::debug!("Failed to load devcert config: {}", e);
            Component::Invalid {
                reason: "Failed to load devcert config".to_string(),
            }
        }
    }
}

/// Checks whether the project config file exists and can be parsed.
fn check_project_config() -> Component {
    if !Project::exists() {
        return Component::Missing;
    }

    match Project::load() {
        Ok(_) => Component::Ok,
        Err(e) => {
            crate::debug!("Failed to load project config: {}", e);
            Component::Invalid {
                reason: "Failed to load project config".to_string(),
            }
        }
    }
}
