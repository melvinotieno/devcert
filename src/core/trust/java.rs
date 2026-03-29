//! Java trust store implementation using the `keytool` command-line utility.
//!
//! This module discovers Java installations by checking the `JAVA_HOME` environment variable,
//! common installation paths, and the system `PATH`. It then interacts with the `cacerts`
//! keystore(s) using `keytool` to check for, install, and uninstall certificates.
//!
//! Note: Modifying the `cacerts` keystore typically requires administrative privileges, so
//! users may need to run DevCert with elevated permissions for these operations to succeed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::Result;

const CACERTS_PASSWORD: &str = "changeit";

impl super::TrustBackend for JavaTrustStore {
    fn check(&self, id: &str) -> bool {
        let alias = Self::alias(id);

        self.exec_keytool(&[
            "-list",
            "-cacerts",
            "-storepass",
            CACERTS_PASSWORD,
            "-alias",
            alias.as_str(),
        ])
    }

    fn install(&self, id: &str, cert_path: &Path) -> Result<()> {
        if self.check(id) {
            crate::debug!("Certificate {:?} already present, skipping install", id);
            return Ok(());
        }

        let alias = Self::alias(id);
        let cert_file = &cert_path.to_string_lossy();

        let args = [
            "-importcert",
            "-cacerts",
            "-storepass",
            CACERTS_PASSWORD,
            "-file",
            cert_file,
            "-alias",
            alias.as_str(),
            "-noprompt",
        ];

        if !self.exec_keytool(&args) {
            anyhow::bail!("Failed to install certificate into Java cacerts keystore");
        }

        Ok(())
    }

    fn uninstall(&self, id: &str) -> Result<()> {
        if !self.check(id) {
            crate::debug!("Certificate {:?} not present, skipping uninstall", id);
            return Ok(());
        }

        let alias = Self::alias(id);

        let args = [
            "-delete",
            "-cacerts",
            "-storepass",
            CACERTS_PASSWORD,
            "-alias",
            alias.as_str(),
        ];

        if !self.exec_keytool(&args) {
            anyhow::bail!("Failed to uninstall certificate from Java cacerts keystore");
        }

        Ok(())
    }
}

/// Trust store implementation for Java (`cacerts` keystore).
pub struct JavaTrustStore {
    /// The root path of the Java installation (JAVA_HOME).
    java_home: PathBuf,
    /// The path to the `cacerts` keystore file.
    cacerts_path: PathBuf,
    /// The path to the `keytool` executable.
    keytool_path: PathBuf,
}

impl JavaTrustStore {
    /// Creates a new instance of `JavaTrustStore` by discovering the Java installation and its tools.
    pub fn new(home: Option<String>) -> Result<Self> {
        if let Some((java_home, cacerts, keytool)) = Self::discover(home) {
            return Ok(Self {
                java_home,
                cacerts_path: cacerts,
                keytool_path: keytool,
            });
        }

        anyhow::bail!(
            "Java installation not found or is invalid. Set `trust.java.home` in your config, \
            set the JAVA_HOME environment variable, or ensure `java` is available on your PATH"
        );
    }

    /// Generates a normalized alias for the certificate based on its ID.
    fn alias(id: &str) -> String {
        let normalized = id.replace(['-', '_', ' '], "");
        format!("{}ca", normalized.to_lowercase())
    }

    /// Discovers the Java installation and its relevant tools (cacerts and keytool) using the following priority:
    /// 1. Configured Java home (from config)
    /// 2. JAVA_HOME environment variable
    /// 3. Java executable on system PATH
    fn discover(home: Option<String>) -> Option<(PathBuf, PathBuf, PathBuf)> {
        // Priority 1: Use configured Java home if provided
        if let Some(home_path) = home {
            crate::debug!("Using configured Java home: {:?}", home_path);

            if let Some((cacerts, keytool)) = Self::find_tools(&home_path) {
                return Some((PathBuf::from(home_path), cacerts, keytool));
            } else {
                crate::report::debug("No valid Java tools found in configured Java home");
            }
        } else {
            crate::report::debug("No configured Java home provided");
        }

        // Priority 2: Check JAVA_HOME environment variable
        if let Ok(env_home) = std::env::var("JAVA_HOME") {
            crate::debug!("JAVA_HOME environment variable points to: {:?}", env_home);

            if let Some((cacerts, keytool)) = Self::find_tools(&env_home) {
                return Some((PathBuf::from(env_home), cacerts, keytool));
            } else {
                crate::report::debug("No valid Java tools found in JAVA_HOME");
            }
        } else {
            crate::report::debug("Environment variable JAVA_HOME not set");
        }

        // Priority 3: Find Java executable on PATH and resolve to root
        if let Some(java_bin) = Self::find_java() {
            if let Some(jre_root) = java_bin.parent().and_then(|p| p.parent()) {
                crate::debug!("Found Java installation via PATH: {:?}", jre_root);

                if let Some((cacerts, keytool)) = Self::find_tools(jre_root.to_str()?) {
                    return Some((PathBuf::from(jre_root), cacerts, keytool));
                } else {
                    crate::report::debug("No valid Java tools found in PATH-resolved Java home");
                }
            }
        } else {
            crate::report::debug("No Java installation found on PATH");
        }

        None
    }

    /// Executes a `keytool` command with the given arguments and returns whether it succeeded.
    fn exec_keytool(&self, args: &[&str]) -> bool {
        let mut cmd = Command::new(&self.keytool_path);
        cmd.args(args);

        let (combined, result) = self.keytool_command(&mut cmd);

        let output = match result {
            Ok(o) => o,
            Err(e) => {
                crate::debug!("Failed to execute keytool: {}", e);
                return false;
            }
        };

        if output.status.success() {
            return true;
        }

        // `-cacerts` was introduced in Java 9. On older versions, keytool will
        // report an illegal option error, hence, fall back to `-keystore <path>`
        if combined.contains("Illegal option: -cacerts") {
            crate::report::debug("keytool lacks -cacerts (pre-Java 9), retrying with -keystore");
            return self.exec_keytool_legacy(args);
        }

        false
    }

    /// Rewrites `-cacerts` to `-keystore <path> -storepass <pass>` for pre-Java 9.
    fn exec_keytool_legacy(&self, args: &[&str]) -> bool {
        let cacerts = &self.cacerts_path.to_string_lossy();

        // Replace the `-cacerts` flag with `-keystore <path> -storepass <pass>`.
        let legacy_args: Vec<&str> = args
            .iter()
            .flat_map(|&a| {
                if a == "-cacerts" {
                    vec!["-keystore", cacerts]
                } else {
                    vec![a]
                }
            })
            .collect();

        crate::debug!("Retrying keytool with legacy -keystore args");

        let mut cmd = Command::new(&self.keytool_path);
        cmd.args(&legacy_args);

        let (_combined, result) = self.keytool_command(&mut cmd);

        result.map(|o| o.status.success()).unwrap_or_else(|e| {
            crate::debug!("Failed to execute keytool (legacy): {}", e);
            false
        })
    }

    /// Executes a `keytool` command and returns the combined stdout/stderr output along with the result.
    fn keytool_command(&self, cmd: &mut Command) -> (String, std::io::Result<Output>) {
        let output = cmd.output();

        if let Ok(ref res) = output {
            let args: Vec<_> = cmd.get_args().collect();

            crate::debug!("keytool command args:\n{:?}", args);

            // Combine stdout and stderr for better error analysis
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&res.stdout),
                String::from_utf8_lossy(&res.stderr)
            )
            .trim()
            .to_string();

            crate::debug!("keytool command output:\n{}", combined);

            // On unix, if the failure is a FileNotFoundException, it likely means we don't
            // have permissions to use keytool, therefore, retry the same command with sudo
            #[cfg(unix)]
            if !res.status.success() && combined.contains("java.io.FileNotFoundException") {
                crate::report::debug(
                    "keytool failed with FileNotFoundException, retrying with sudo",
                );

                let mut sudo_cmd = Command::new("sudo");

                // Preserve JAVA_HOME in the environment for the sudo command
                sudo_cmd
                    .arg("env")
                    .arg(format!("JAVA_HOME={}", self.java_home.display()))
                    .arg(&self.keytool_path)
                    .args(args);

                let sudo_output = sudo_cmd.output();

                return match sudo_output {
                    Ok(sudo_res) => {
                        let sudo_combined = format!(
                            "{}{}",
                            String::from_utf8_lossy(&sudo_res.stdout),
                            String::from_utf8_lossy(&sudo_res.stderr)
                        )
                        .trim()
                        .to_string();

                        crate::debug!("sudo keytool command output:\n{}", sudo_combined);

                        (sudo_combined, Ok(sudo_res))
                    }
                    Err(e) => {
                        crate::debug!("Failed to execute sudo keytool: {}", e);
                        (String::new(), Err(e))
                    }
                };
            }

            return (combined, output);
        }

        (String::new(), output)
    }

    /// Finds the `cacerts` and `keytool` paths within a given Java home directory.
    fn find_tools(root: &str) -> Option<(PathBuf, PathBuf)> {
        let cacerts = Self::find_cacerts(root)?;
        let keytool = Self::find_keytool(root)?;

        Some((cacerts, keytool))
    }

    /// Finds the path to the `cacerts` keystore within the Java installation.
    fn find_cacerts(root: &str) -> Option<PathBuf> {
        let root_path = PathBuf::from(root);

        for relative in &["lib/security/cacerts", "jre/lib/security/cacerts"] {
            let candidate = root_path.join(relative);

            if candidate.exists() {
                crate::debug!("Found cacerts keystore at: {:?}", candidate);
                return Some(candidate);
            } else {
                crate::debug!("No cacerts keystore found at: {:?}", candidate);
            }
        }

        None
    }

    /// Finds the path to the `keytool` executable within the Java installation.
    fn find_keytool(root: &str) -> Option<PathBuf> {
        let keytool = if cfg!(target_os = "windows") {
            "keytool.exe"
        } else {
            "keytool"
        };

        let candidate = PathBuf::from(root).join("bin").join(keytool);

        if candidate.exists() {
            crate::debug!("Found keytool at: {:?}", candidate);
            candidate.canonicalize().ok().or(Some(candidate))
        } else {
            crate::debug!("No keytool found at: {:?}", candidate);
            None
        }
    }

    /// Finds the path to the Java executable.
    fn find_java() -> Option<PathBuf> {
        let path = which::which("java").ok()?;
        path.canonicalize().ok().or(Some(path))
    }
}
