//! Command implementations for DevCert CLI.

mod init;

use anyhow::Result;

use crate::cli::commands::init::init_project;

/// Initializes a new DevCert project in the current directory.
pub fn init() -> Result<()> {
    init_project()
}
