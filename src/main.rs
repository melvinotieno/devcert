mod cli;
mod config;
mod core;
mod log;
mod trust;

use clap::Parser;

fn run() -> anyhow::Result<()> {
    cli::Cli::parse().command.execute()
}

fn main() {
    if let Err(e) = run() {
        log::fatal(&e);
        std::process::exit(1);
    }
}
