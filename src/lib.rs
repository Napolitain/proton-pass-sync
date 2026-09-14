#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]

pub mod cli;
pub mod config;
pub mod delivery;
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
    let mut loaded = config::Config::load(cli.config.as_deref())?;
    if let Some(path) = cli.state_dir {
        anyhow::ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "state directory must be an absolute path without parent components"
        );
        loaded.state_dir = path;
    }

    match cli.command {
        Command::ExportCiphertext { output } => delivery::export(&loaded, &output),
        Command::ImportCiphertext {
            input,
            dry_run,
            accept_remote,
        } => delivery::import(&loaded, &input, dry_run, &accept_remote),
        Command::Doctor => sync::doctor(&loaded),
        Command::Sync {
            dry_run,
            full,
            accept_remote,
        } => sync::synchronize(&loaded, dry_run, full, &accept_remote),
        Command::Status { json } => sync::status(&loaded, json),
        Command::Prune { path } => {
            anyhow::ensure!(
                !loaded.state_dir.join("ciphertext-consumer").exists(),
                "pruning a ciphertext consumer is unsupported; prune the producer explicitly"
            );
            sync::prune(&loaded, &path)
        }
    }
}
