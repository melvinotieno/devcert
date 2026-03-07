//! Command-line interface for DevCert.

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
    /// Initializes a new DevCert project in the current directory.
    Init,
}
