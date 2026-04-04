//! NSS trust store implementation.
//!
//! This module discovers NSS certificate databases by scanning common profile directories for
//! Firefox, Chrome, and other Chromium-based browsers. It then uses the `certutil` command-line
//! tool to check for, install, and uninstall certificates in these databases.
//!
//! Note: Modifying NSS databases typically requires administrative privileges, so users
//! may need to run DevCert with elevated permissions for these operations to succeed.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

impl super::TrustBackend for NssTrustStore {
    fn check(&self, id: &str) -> bool {
        if self.profiles.is_empty() {
            return true;
        }

        let nickname = Self::cert_nickname(id);
        self.profiles.iter().all(|db| Self::is_in_db(db, &nickname))
    }

    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        let nickname = Self::cert_nickname(id);
        let mut errors: Vec<String> = Vec::new();

        for db in &self.profiles {
            if Self::is_in_db(db, &nickname) {
                continue;
            }

            if let Err(e) = Self::add_to_db(db, cert_path, &nickname) {
                errors.push(format!("{} — {:?}", e, db.dir));
            }
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to install certificate into {} NSS database(s):\n{}",
                errors.len(),
                errors.join("\n")
            );
        }

        Ok(())
    }

    fn uninstall(&self, id: &str) -> Result<()> {
        let nickname = Self::cert_nickname(id);
        let mut errors: Vec<String> = Vec::new();

        for db in &self.profiles {
            if !Self::is_in_db(db, &nickname) {
                continue;
            }

            if let Err(e) = Self::remove_from_db(db, &nickname) {
                errors.push(format!("{} — {:?}", e, db.dir));
            }
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to remove certificate from {} NSS database(s):\n{}",
                errors.len(),
                errors.join("\n")
            );
        }

        Ok(())
    }
}

/// Trust store implementation targeting NSS certificate databases.
pub struct NssTrustStore {
    certutil_path: PathBuf,
    profiles: Vec<NssDatabase>,
}

impl NssTrustStore {
    /// Discovers all NSS databases on the system and returns a new store handle.
    pub fn new(profile_dirs: Vec<String>) -> Result<Self> {
        let certutil_path = Self::find_certutil();
        let profiles = Self::discover_profiles(profile_dirs);

        if certutil_path.is_none() {
            anyhow::bail!(
                "Unable to find `certutil` in PATH. NSS trust store operations will be unavailable. \
                Please install `nss-tools` and ensure `certutil` is on your PATH."
            );
        }

        if profiles.is_empty() {
            anyhow::bail!(
                "No NSS certificate databases found. NSS trust store operations will be unavailable."
            );
        }

        Ok(Self {
            certutil_path,
            profiles,
        })
    }

    fn discover_profiles(dirs: Vec<String>) -> Vec<NssDatabase> {
        let mut profiles = Vec::new();

        // NSS databases
        for root in Self::get_nss_dbs() {
            if let Some(db) = Self::classify(&root) {
                profiles.push(db);
            }
        }

        // Firefox profiles
        for pattern in Self::get_firefox_profile_globs() {
            if let Ok(entries) = glob::glob(&pattern) {
                for entry in entries.flatten() {
                    if let Some(db) = Self::classify(&entry) {
                        profiles.push(db);
                    }
                }
            }
        }

        // Additional custom profile directories specified by the user
        for pattern in dirs {
            if let Ok(entries) = glob::glob(&pattern) {
                for entry in entries.flatten() {
                    if let Some(db) = Self::classify(&entry) {
                        profiles.push(db);
                    }
                }
            }
        }

        profiles
    }

    fn get_nss_dbs() -> Vec<PathBuf> {
        let mut dbs = Vec::new();

        if let Some(home) = std::env::home_dir() {
            // Common location for NSS databases
            dbs.push(home.join(".pki/nssdb"));

            // Snapcraft chromium NSS database location
            dbs.push(home.join("snap/chromium/current/.pki/nssdb"));
        } else {
            crate::report::debug("Unable to determine home directory for NSS database discovery");
        }

        // CentOS 7 NSS database location
        dbs.push(PathBuf::from("/etc/pki/nssdb"));

        dbs
    }

    #[cfg(target_os = "linux")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();

        if let Some(home) = std::env::home_dir().map(|h| h.display().to_string()) {
            globs.extend([
                format!("{}/.mozilla/firefox/*", home),
                format!("{}/snap/firefox/common/.mozilla/firefox/*", home),
            ]);
        }

        globs
    }

    #[cfg(target_os = "macos")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();

        if let Some(home) = std::env::home_dir().map(|h| h.display().to_string()) {
            globs.push(format!(
                "{}/Library/Application Support/Firefox/Profiles/*",
                home
            ));
        }

        globs
    }

    #[cfg(target_os = "windows")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();

        if let Some(profile) = std::env::var("USERPROFILE") {
            globs.push(format!(
                "{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*",
                profile
            ));
        }

        globs
    }

    fn classify(dir: &Path) -> Option<NssDatabase> {
        if dir.join("cert9.db").exists() {
            Some(NssDatabase {
                dir: dir.to_owned(),
                format: NssFormat::Sql,
            })
        } else if dir.join("cert8.db").exists() {
            Some(NssDatabase {
                dir: dir.to_owned(),
                format: NssFormat::Dbm,
            })
        } else {
            None
        }
    }

    fn find_certutil() -> Option<PathBuf> {
        if let Ok(path) = which::which("certutil") {
            crate::debug!("Found certutil at: {:?}", path);
            return Some(path.canonicalize().unwrap_or(path));
        }

        #[cfg(target_os = "macos")]
        {
            // Check common Homebrew hardcoded locations first as a fast path
            // /usr/local is the Intel default; /opt/homebrew is Apple Silicon
            let brew_paths = [
                "usr/local/opt/nss/bin/certutil",
                "opt/homebrew/opt/nss/bin/certutil",
            ];

            for path in brew_paths {
                let brew_path = PathBuf::from(path);
                if brew_path.exists() {
                    crate::debug!("Found certutil at Homebrew path: {:?}", brew_path);
                    return Some(brew_path.canonicalize().unwrap_or(brew_path));
                }
            }

            // Fallback to asking Homebrew directly, but only if we can find brew
            // itself to avoid hanging or erroring where homebrew may not be on PATH
            let brew_bin = which::which("brew").ok().or_else(|| {
                // Homebrew's canonical locations as last resort
                ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
                    .iter()
                    .map(PathBuf::from)
                    .find(|p| p.exists())
            });

            if let Some(brew) = brew_bin {
                match Command::new(brew).args(["--prefix", "nss"]).output() {
                    Ok(output) if output.status.success() => {
                        let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        let path = PathBuf::from(prefix).join("bin/certutil");

                        if path.exists() {
                            crate::debug!("Found certutil via Homebrew prefix: {:?}", path);
                            return Some(path.canonicalize().unwrap_or(path));
                        }
                    }
                    Ok(output) => {
                        crate::debug!(
                            "`brew --prefix nss` failed ({}): {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr).trim(),
                        );
                    }
                    Err(e) => {
                        crate::debug!("Failed to execute brew to find certutil: {}", e);
                    }
                }
            }
        }

        None
    }
}

/// A single NSS certificate database together with its format version.
#[derive(Debug, Clone)]
struct NssDatabase {
    /// Directory containing the NSS database files (`cert9.db` or `cert8.db`).
    dir: PathBuf,
    /// Format of the NSS database, determined by the presence of `cert9.db` (SQLite) or `cert8.db` (DBM).
    format: NssFormat,
}

impl NssDatabase {
    /// Returns the appropriate `-d` argument for `certutil` based on the database format and directory.
    fn certutil_dir_arg(&self) -> String {
        format!("{}{}", self.format.prefix(), self.dir.display())
    }
}

/// NSS database file format, selected by the prefix passed to `certutil -d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NssFormat {
    /// Newer SQLite-backed format (`cert9.db`). Prefix: `sql:`.
    Sql,
    /// Legacy Berkeley DB format (`cert8.db`). Prefix: `dbm:`.
    Dbm,
}

impl NssFormat {
    /// Returns the required prefix for `certutil -d` based on the NSS database format.
    fn prefix(self) -> &'static str {
        match self {
            NssFormat::Sql => "sql:",
            NssFormat::Dbm => "dbm:",
        }
    }
}
