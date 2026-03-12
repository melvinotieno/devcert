//! Configuration types for devcert.
//!
//! Two layers of configuration are provided:
//!
//! - [`devcert`]: Global, user-level configuration stored in `~/.devcert/config.toml`
//!   (or the path given by `DEVCERT_HOME`).
//! - [`project`]: Per-project configuration stored in `./devcert.toml` within a project directory.

pub mod devcert;
pub mod project;
