#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]

pub mod cli;
pub mod config;
pub mod manifest;
pub mod paths;
pub mod process;
pub mod proton;
pub mod store;
pub mod sync;

use anyhow::{Context, Result};
use cli::{Cli, Command};

pub fn run(cli: Cli) -> Result<()> {
    process::disable_core_dumps().context("security initialization failed")?;
    let loaded = config::Config::load(cli.config.as_deref())?;

    match cli.command {
        Command::Doctor => sync::doctor(&loaded),
        Command::Sync {
            dry_run,
            full,
            accept_remote,
        } => sync::synchronize(&loaded, dry_run, full, &accept_remote),
        Command::Status { json } => sync::status(&loaded, json),
        Command::Prune { path } => sync::prune(&loaded, &path),
    }
}
