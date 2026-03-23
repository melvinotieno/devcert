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
    /// Returns the name of the trust store.
    fn name(&self) -> &str {
        "NSS"
    }

    /// Returns `true` if the certificate is present in **all** discovered NSS databases.
    fn check(&self, id: &str) -> bool {
        if self.db_dirs.is_empty() {
            return true;
        }

        let nickname = Self::cert_nickname(id);
        self.db_dirs.iter().all(|db| Self::is_in_db(db, &nickname))
    }

    /// Installs the certificate into every discovered NSS database.
    ///
    /// Databases where the certificate is already present are skipped.
    /// Failures across individual databases are aggregated into a single error.
    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        let nickname = Self::cert_nickname(id);
        let mut errors: Vec<String> = Vec::new();

        for db in &self.db_dirs {
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

    /// Removes the certificate from every NSS database that contains it.
    fn uninstall(&self, id: &str) -> Result<()> {
        let nickname = Self::cert_nickname(id);
        let mut errors: Vec<String> = Vec::new();

        for db in &self.db_dirs {
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
    /// List of discovered NSS databases on the system, each with its directory and format.
    db_dirs: Vec<NssDatabase>,
}

impl NssTrustStore {
    /// Discovers all NSS databases on the system and returns a new store handle.
    pub fn new() -> Result<Self> {
        Ok(Self {
            db_dirs: Self::discover_databases(),
        })
    }

    /// Returns the nickname used to identify the certificate inside NSS databases.
    fn cert_nickname(id: &str) -> String {
        format!("devcert-{}", id)
    }

    /// Discovers NSS databases by scanning common profile directories for Firefox, Chrome, and other
    /// Chromium-based browsers, as well as the default NSS database location.
    fn discover_databases() -> Vec<NssDatabase> {
        let home = match env::home_dir() {
            Some(h) => h,
            None => return Vec::new(),
        };

        let profile_roots: &[PathBuf] = &[
            home.join(".mozilla/firefox"),
            home.join("Library/Application Support/Firefox/Profiles"),
            home.join(".config/chromium"),
            home.join(".config/google-chrome"),
            home.join("Library/Application Support/Google/Chrome"),
            home.join(".config/BraveSoftware/Brave-Browser"),
            home.join(".pki/nssdb"),
        ];

        let mut databases = Vec::new();

        for root in profile_roots {
            if !root.exists() {
                continue;
            }

            if Self::is_nss_dir(root) {
                if let Some(db) = Self::classify(root) {
                    databases.push(db);
                }
                continue;
            }

            let entries = match std::fs::read_dir(root) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() && Self::is_nss_dir(&path) {
                    if let Some(db) = Self::classify(&path) {
                        databases.push(db);
                    }
                }
            }
        }

        databases
    }

    /// Checks if the given directory contains files characteristic of an NSS database (`cert9.db` or `cert8.db`).
    fn is_nss_dir(dir: &Path) -> bool {
        dir.join("cert9.db").exists() || dir.join("cert8.db").exists()
    }

    /// Classifies the NSS database format (SQLite or DBM) based on the presence of `cert9.db` or
    /// `cert8.db` files in the directory.
    ///
    /// Returns `None` if neither file is found, indicating that the directory is not a valid NSS database.
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

    /// Runs the `certutil` command with the specified arguments and checks for successful execution.
    fn run_certutil(args: &[&str]) -> Result<()> {
        let status = Command::new("certutil")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .with_context(|| format!("Failed to run: certutil {}", args.join(" ")))?;

        if !status.success() {
            anyhow::bail!("certutil failed — is `nss-tools` installed?");
        }

        Ok(())
    }

    /// Checks if the given nickname exists in the specified NSS database.
    fn is_in_db(db: &NssDatabase, nickname: &str) -> bool {
        Command::new("certutil")
            .args(["-L", "-d", &db.certutil_dir_arg(), "-n", nickname])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Adds the certificate to the specified NSS database with the given nickname.
    fn add_to_db(db: &NssDatabase, cert_path: &Path, nickname: &str) -> Result<()> {
        Self::run_certutil(&[
            "-A",
            "-d",
            &db.certutil_dir_arg(),
            "-n",
            nickname,
            "-t",
            "CT,,", // trusted CA for SSL client & server
            "-i",
            &cert_path.to_string_lossy(),
        ])
    }

    /// Deletes the certificate with the given nickname from the specified NSS database.
    fn remove_from_db(db: &NssDatabase, nickname: &str) -> Result<()> {
        Self::run_certutil(&["-D", "-d", &db.certutil_dir_arg(), "-n", nickname])
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
