//! Path management utilities for devcert configuration.
//!
//! This module provides functions to locate devcert configuration
//! directories and files for both global and project-specific use.
//!
//! # Paths
//!
//! - **Global directory**: `~/.devcert`
//! - **Global config file**: `~/.devcert/config.toml`
//! - **Project directory**: `./.devcert`
//! - **Project config file**: `./.devcert.toml`

use std::{env, path};

use anyhow::{Context, Result};

/// The default directory name for devcert configuration.
pub const DIR: &str = ".devcert";

/// Gets the global base directory path for devcert.
///
/// # Returns
///
/// A `PathBuf` pointing to `~/.devcert`.
pub fn get_global_base_path() -> Result<path::PathBuf> {
    Ok(env::home_dir()
        .context("Failed to get home directory")?
        .join(DIR))
}

/// Gets the path to the global configuration file.
///
/// # Returns
///
/// A `PathBuf` pointing to `~/.devcert/config.toml`.
pub fn get_global_config_path() -> Result<path::PathBuf> {
    Ok(get_global_base_path()?.join("config.toml"))
}

/// Gets the project-specific base directory path for devcert.
///
/// # Returns
///
/// A `PathBuf` pointing to `./.devcert` relative to the current working directory.
pub fn get_project_base_path() -> Result<path::PathBuf> {
    Ok(env::current_dir()?.join(DIR))
}

/// Gets the path to the project-specific configuration file.
///
/// # Returns
///
/// A `PathBuf` pointing to `./.devcert.toml` relative to the current working directory.
pub fn get_project_config_path() -> Result<path::PathBuf> {
    Ok(env::current_dir()?.join(".devcert.toml"))
}
