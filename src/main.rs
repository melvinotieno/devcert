mod cli;
mod config;
mod core;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            cli::commands::init()?;
        }
    }

    Ok(())
}
