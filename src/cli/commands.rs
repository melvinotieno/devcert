//! Implementations of the DevCert CLI subcommands.
//!
//! Each subcommand is defined in its own submodule and re-exported here
//! for use by the [`super::Commands`] dispatcher.

mod install;

pub use install::install;
