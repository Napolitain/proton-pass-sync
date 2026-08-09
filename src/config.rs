use crate::paths::validate_pass_path;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_STALE_AFTER_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug)]
pub struct Config {
    pub vault_share_id: String,
    pub password_store_dir: PathBuf,
    pub target_prefix: String,
    pub proton_cli: PathBuf,
    pub pass_command: PathBuf,
    pub gpg_command: PathBuf,
    pub stale_after_secs: u64,
}

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub config: Config,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    schema_version: u32,
    vault_share_id: String,
    password_store_dir: Option<PathBuf>,
    #[serde(default)]
    target_prefix: String,
    proton_cli: Option<PathBuf>,
    pass_command: Option<PathBuf>,
    gpg_command: Option<PathBuf>,
    #[serde(default = "default_stale_after_secs")]
    stale_after_secs: u64,
}

const fn default_stale_after_secs() -> u64 {
    DEFAULT_STALE_AFTER_SECS
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<LoadedConfig> {
        let config_path = match path {
            Some(path) => path.to_path_buf(),
            None => default_config_path()?,
        };
        let mut source = fs::read_to_string(&config_path)
            .with_context(|| format!("cannot read configuration at {}", config_path.display()))?;
        let parsed = Self::parse(&source);
        source.zeroize();
        let config = parsed?;
        let state_dir = default_state_dir()?;
        Ok(LoadedConfig {
            config,
            config_path,
            state_dir,
        })
    }

    fn parse(source: &str) -> Result<Self> {
        let raw: ConfigFile = toml::from_str(source).map_err(|_| {
            anyhow::anyhow!(
                "invalid configuration (details withheld): unknown field or malformed value"
            )
        })?;
        if raw.schema_version != CONFIG_SCHEMA_VERSION {
            bail!(
                "unsupported configuration schema_version {}; expected {}",
                raw.schema_version,
                CONFIG_SCHEMA_VERSION
            );
        }
        if raw.vault_share_id.trim().is_empty() || raw.vault_share_id.chars().any(char::is_control)
        {
            bail!("vault_share_id must be a nonempty single-line identifier");
        }
        if raw.stale_after_secs == 0 {
            bail!("stale_after_secs must be greater than zero");
        }

        let home = home_dir()?;
        let password_store_dir = raw
            .password_store_dir
            .unwrap_or_else(|| home.join(".password-store"));
        if !password_store_dir.is_absolute() {
            bail!("password_store_dir must be absolute");
        }
        if !is_clean_absolute_path(&password_store_dir) {
            bail!("password_store_dir must not contain dot or parent components");
        }
        if password_store_dir.parent().is_none() {
            bail!("password_store_dir must not be a filesystem root");
        }

        let target_prefix = if raw.target_prefix.is_empty() {
            String::new()
        } else {
            validate_pass_path(&raw.target_prefix).context("invalid target_prefix")?
        };

        let proton_cli = command_path(raw.proton_cli, "pass-cli", "proton_cli")?;
        let pass_command = command_path(raw.pass_command, "pass", "pass_command")?;
        let gpg_command = command_path(raw.gpg_command, "gpg", "gpg_command")?;

        Ok(Self {
            vault_share_id: raw.vault_share_id,
            password_store_dir,
            target_prefix,
            proton_cli,
            pass_command,
            gpg_command,
            stale_after_secs: raw.stale_after_secs,
        })
    }
}

fn command_path(value: Option<PathBuf>, default: &str, key: &str) -> Result<PathBuf> {
    match value {
        Some(path) if is_clean_absolute_path(&path) => Ok(path),
        Some(_) => bail!("{key} override must be an absolute path"),
        None => Ok(PathBuf::from(default)),
    }
}

fn default_config_path() -> Result<PathBuf> {
    if let Some(base) = env::var_os("XDG_CONFIG_HOME") {
        let base = PathBuf::from(base);
        if !is_clean_absolute_path(&base) {
            bail!("XDG_CONFIG_HOME must be a clean absolute path");
        }
        return Ok(base.join("proton-pass-sync/config.toml"));
    }
    Ok(home_dir()?.join(".config/proton-pass-sync/config.toml"))
}

fn default_state_dir() -> Result<PathBuf> {
    if let Some(base) = env::var_os("XDG_STATE_HOME") {
        let base = PathBuf::from(base);
        if !is_clean_absolute_path(&base) {
            bail!("XDG_STATE_HOME must be a clean absolute path");
        }
        return Ok(base.join("proton-pass-sync"));
    }
    Ok(home_dir()?.join(".local/state/proton-pass-sync"))
}

fn home_dir() -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    if !is_clean_absolute_path(&home) {
        bail!("HOME must be a clean absolute path");
    }
    Ok(home)
}

fn is_clean_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> &'static str {
        r#"
schema_version = 1
vault_share_id = "share-id"
password_store_dir = "/tmp/password-store"
"#
    }

    #[test]
    fn parses_minimal_config() {
        let config = Config::parse(base()).unwrap();
        assert_eq!(config.vault_share_id, "share-id");
        assert_eq!(config.target_prefix, "");
        assert_eq!(config.stale_after_secs, 86_400);
        assert_eq!(config.proton_cli, PathBuf::from("pass-cli"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let source = format!("{}\ntoken = 'never'\n", base());
        assert!(Config::parse(&source).is_err());
    }

    #[test]
    fn parse_errors_do_not_echo_source_secrets() {
        let source = format!("{}\npat = 'fake-top-secret-value'\n", base());
        let error = Config::parse(&source).unwrap_err().to_string();
        assert!(!error.contains("fake-top-secret-value"));
    }

    #[test]
    fn requires_absolute_command_overrides() {
        let source = format!("{}\nproton_cli = 'bin/pass-cli'\n", base());
        assert!(Config::parse(&source).is_err());
    }

    #[test]
    fn rejects_non_normal_absolute_paths() {
        let store = base().replace(
            "password_store_dir = \"/tmp/password-store\"",
            "password_store_dir = \"/tmp/../password-store\"",
        );
        assert!(Config::parse(&store).is_err());

        let command = format!("{}\nproton_cli = '/tmp/../bin/pass-cli'\n", base());
        assert!(Config::parse(&command).is_err());
    }

    #[test]
    fn rejects_future_schema() {
        let source = base().replace("schema_version = 1", "schema_version = 2");
        assert!(Config::parse(&source).is_err());
    }
}
