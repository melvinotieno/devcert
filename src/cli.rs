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
    Init,
}
