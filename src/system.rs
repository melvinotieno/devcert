//! Lazily-evaluated, cached system health status.
//!
//! Each component is computed at most once (via [`OnceLock`]) and may depend
//! on earlier components — e.g. `config` and `ca` are skipped if `home` is not OK.
//!
//! Dependency order: `home` → `config`, `ca` → `trust`

mod checks;
mod component;

pub mod dir;
pub mod file;

use std::path::PathBuf;
use std::sync::OnceLock;

pub use component::Component;

use crate::config::devcert::CaRoot;
use crate::config::devcert::DevCert;

use self::dir::DirError;

/// Represents the overall health status of the system, with lazily-evaluated components.
pub struct SystemStatus {
    /// Determines whether to use the global DevCert root or a project-scoped root.
    root: CaRoot,
    /// Resolved home directory path for the active root. `DirError` if resolution failed.
    dir: OnceLock<Result<PathBuf, DirError>>,
    /// Loaded DevCert config, or an error string if it failed to load.
    devcert: OnceLock<Result<DevCert, String>>,
    /// Status of the home directory.
    home: OnceLock<Component>,
    /// Status of the relevant config file (DevCert or project).
    config: OnceLock<Component>,
    /// Status of the local Certificate Authority.
    ca: OnceLock<Component>,
    /// Status of the CA's presence in system trust stores.
    trust: OnceLock<Component>,
}

impl SystemStatus {
    /// Creates a new `SystemStatus` for the given CA root scope.
    ///
    /// No checks are run until individual components are accessed.
    pub fn new(root: CaRoot) -> Self {
        crate::debug!("Initializing system status with root: {:?}", root);

        Self {
            root,
            dir: OnceLock::new(),
            devcert: OnceLock::new(),
            home: OnceLock::new(),
            config: OnceLock::new(),
            ca: OnceLock::new(),
            trust: OnceLock::new(),
        }
    }

    /// Returns `true` only if all components are healthy.
    ///
    /// Triggers evaluation of all components if not already cached.
    pub fn is_ok(&self) -> bool {
        let home = self.home();
        let config = self.config();
        let ca = self.ca();
        let trust = self.trust();

        let status = home.is_ok() && config.is_ok() && ca.is_ok() && trust.is_ok();

        crate::debug!(
            "System status: home={:?}, config={:?}, ca={:?}, trust={:?} => overall={}",
            home.is_ok(),
            config.is_ok(),
            ca.is_ok(),
            trust.is_ok(),
            status
        );

        status
    }

    /// Returns the status of the home directory.
    pub fn home(&self) -> &Component {
        self.home.get_or_init(|| match self.dir() {
            Ok(_) => Component::Ok,
            Err(DirError::Missing) => Component::Missing,
            Err(DirError::Invalid(reason)) => Component::Invalid {
                reason: reason.clone(),
            },
        })
    }

    /// Returns the status of the config file.
    ///
    /// Skipped automatically if the home directory is not OK.
    pub fn config(&self) -> &Component {
        self.config.get_or_init(|| match self.dir() {
            Ok(_) => checks::check_config(&self.root, self.devcert()),
            _ => Component::Skipped {
                because: "Home directory does not exist or is invalid",
            },
        })
    }

    /// Returns the status of the local Certificate Authority.
    ///
    /// Skipped automatically if the home directory is not OK.
    pub fn ca(&self) -> &Component {
        self.ca.get_or_init(|| match self.dir() {
            Ok(path) => checks::check_ca(path),
            _ => Component::Skipped {
                because: "Home directory does not exist or is invalid",
            },
        })
    }

    /// Returns the trust store status for the CA certificate.
    ///
    /// Skipped automatically if the CA is not OK.
    pub fn trust(&self) -> &Component {
        self.trust.get_or_init(|| match self.ca() {
            Component::Ok => checks::check_trust(&self.root, self.devcert()),
            _ => Component::Skipped {
                because: "Certificate authority does not exist or is invalid",
            },
        })
    }

    /// Returns a reference to the loaded DevCert config, loading it on first access.
    ///
    /// Returns an `Err(&str)` if loading failed, which callers can use to skip dependent checks.
    fn devcert(&self) -> Result<&DevCert, &str> {
        self.devcert
            .get_or_init(|| DevCert::load().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| e.as_str())
    }

    /// Returns the resolved home directory path, or `DirErr` if resolution failed.
    fn dir(&self) -> Result<&PathBuf, &DirError> {
        self.dir
            .get_or_init(|| dir::resolve_dir(&self.root))
            .as_ref()
    }
}
