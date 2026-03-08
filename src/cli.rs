//! Command-line interface for DevCert.
//!
//! This module defines the structure of the CLI and the commands
//! available to the user. It does not execute command logic directly.
//!
//! Command implementations are located in `src/cli/commands` and they
//! are invoked from the `main.rs` entry point.

pub mod commands;

use clap::{Parser, Subcommand};

/// DevCert is a tool for managing local development SSL certificates.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize DevCert for the current project.
    Init,
    /// Clean DevCert artifacts for the current project.
    Clean,
}
