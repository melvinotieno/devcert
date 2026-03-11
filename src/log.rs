use anyhow::Error;
use colored::Colorize;

pub fn fatal(err: &Error) {
    eprintln!("{}", format!("{:#}", err).red().bold());
}
