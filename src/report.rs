//! Logger utilities for DevCert's CLI output.
//!
//! Provides functions and macros for displaying styled, colored messages to the user.
//! All diagnostic output (`warn`, `error`, `fatal`, `debug`) goes to `stderr`, while
//! user-facing output (`success`, `info`) goes to `stdout`.
//!
//! Each logger has both a function (for plain `&str`) and a macro (for formatted strings):
//!
//! ```no_run
//! // Function
//! info("Certificate generated");
//!
//! // Macro
//! info!("Certificate generated for {}", domain);
//! ```
//!
//! Debug output is suppressed unless the `DEVCERT_DEBUG` environment variable is set.

use anyhow::Error;
use colored::Colorize;

/// Prints a success message.
pub fn success(msg: &str) {
    println!("{}", msg.green().bold());
}

/// Prints an informational message.
pub fn info(msg: &str) {
    println!("{}", msg.blue().bold());
}

/// Prints a warning message.
pub fn warn(msg: &str) {
    eprintln!("{}", msg.yellow().bold());
}

/// Prints an error message.
pub fn error(msg: &str) {
    eprintln!("{}", msg.red().bold());
}

/// Prints an [`anyhow::Error`] with its full cause chain.
///
/// Uses `{:#}` formatting to include the complete chain of causes, e.g.:
/// `failed to read config file: No such file or directory (os error 2)`
pub fn fatal(err: &Error) {
    eprintln!("{}", format!("{:#}", err).red().bold());
}

/// Prints a debug message.
///
/// Output is suppressed unless the `DEVCERT_DEBUG` environment variable is set:
///
/// ```bash
/// DEVCERT_DEBUG=true devcert init
/// ```
pub fn debug(msg: &str) {
    if std::env::var("DEVCERT_DEBUG").is_ok() {
        eprintln!("{}", msg.cyan().bold());
    }
}

/// Prints a formatted success message.
///
/// ```no_run
/// success!("Certificate issued for {}", domain);
/// ```
#[macro_export]
macro_rules! success {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("{}", format!($($arg)*).green().bold())
    }};
}

/// Prints a formatted informational message.
///
/// ```no_run
/// info!("Trusting CA for {} domains", count);
/// ```
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("{}", format!($($arg)*).blue().bold())
    }};
}

/// Prints a formatted warning message.
///
/// ```no_run
/// warn!("Certificate for {} expires in {} days", domain, days);
/// ```
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        eprintln!("{}", format!($($arg)*).yellow().bold())
    }};
}

/// Prints a formatted error message.
///
/// ```no_run
/// error!("Failed to write to {}", path);
/// ```
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        eprintln!("{}", format!($($arg)*).red().bold())
    }};
}

/// Prints a formatted debug message.
///
/// Output is suppressed unless the `DEVCERT_DEBUG` environment variable is set.
///
/// ```no_run
/// debug!("Resolved config path: {}", path);
/// ```
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        if std::env::var("DEVCERT_DEBUG").is_ok() {
            eprintln!("{}", format!($($arg)*).cyan().bold())
        }
    }};
}
