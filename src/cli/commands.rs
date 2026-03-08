//! Command implementations for DevCert CLI.
//!
//! Each command is implemented in its own module under `cli/commands`.

mod clean;
mod init;

use anyhow::Result;

use crate::cli::commands::{clean::clean_project, init::init_project};

/// Initializes a new DevCert project in the current directory.
pub fn init() -> Result<()> {
    init_project()
}

/// Cleans up the DevCert project in the current directory.
pub fn clean() -> Result<()> {
    clean_project()
}
