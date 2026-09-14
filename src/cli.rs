use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Path to a versioned TOML configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the private transaction state directory.
    #[arg(long, global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Publish a complete ciphertext-only snapshot from a private mirror.
    ExportCiphertext {
        #[arg(long)]
        output: PathBuf,
    },
    /// Install ciphertext without contacting Proton or invoking GPG.
    ImportCiphertext {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        accept_remote: Vec<String>,
    },
    /// Verify the Proton session and local password-store prerequisites.
    Doctor,
    /// Synchronize active Proton custom fields into GNU pass.
    Sync {
        /// Report inventory changes and conflicts without reading secrets or writing state.
        #[arg(long)]
        dry_run: bool,
        /// Refetch every active custom item.
        #[arg(long)]
        full: bool,
        /// Overwrite and adopt one exact conflicting GNU pass path.
        #[arg(long, value_name = "PATH")]
        accept_remote: Vec<String>,
    },
    /// Report cache freshness and conflict counts.
    Status {
        /// Emit a stable machine-readable JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Permanently remove one retained entry after confirmation.
    Prune {
        /// Exact GNU pass path recorded by the manifest.
        path: String,
    },
}
