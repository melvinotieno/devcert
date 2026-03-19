//! DevCert
//!
//! A simple CLI tool for generating and managing local development TLS certificates.
//!
//! At its core, DevCert provides a local certificate authority (CA) and the ability to generate
//! leaf certificates signed by that CA. It also includes functionality for managing trust stores,
//! allowing users to easily add the CA certificate to their system's trusted certificates.

mod cli;
mod config;
mod core;
mod report;

use clap::Parser;

fn run() -> anyhow::Result<()> {
    cli::Cli::parse().command.execute()
}

fn main() {
    if let Err(error) = run() {
        report::fatal(&error);
        std::process::exit(1);
    }
}
