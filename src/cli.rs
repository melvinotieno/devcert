//! Command-line interface for DevCert.
//!
//! Defines the top-level [`Cli`] parser and the [`Commands`] enum, which
//! maps each subcommand to its implementation in the [`commands`] module.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "devcert")]
#[command(version)]
#[command(about = "A local CA for development with trusted TLS certificates")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate a local CA and install it into the system trust stores.
    Install,
}

impl Commands {
    /// Executes the subcommand.
    ///
    /// # Errors
    ///
    /// Returns an error if the subcommand fails.
    pub fn execute(&self) -> anyhow::Result<()> {
        match self {
            Commands::Install => commands::install(),
        }
    }
}
