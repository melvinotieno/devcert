//! DevCert
//!
//! A simple CLI tool for generating and managing local development TLS certificates.
//!
//! It creates a local Certificate Authority (CA), adds it to the system trust store,
//! and issues certificates for development domains.

mod cli;
mod config;
mod core;
mod report;
mod trust;

use clap::Parser;

fn run() -> anyhow::Result<()> {
    cli::Cli::parse().command.execute()
}

fn main() {
    if let Err(e) = run() {
        report::fatal(&e);
        std::process::exit(1);
    }
}
