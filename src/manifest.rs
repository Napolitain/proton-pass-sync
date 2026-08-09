use crate::config::{Config, LoadedConfig};
use crate::paths::validate_path_graph;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub vault_share_id: String,
    pub password_store_dir: PathBuf,
    pub target_prefix: String,
    pub last_success_at: Option<DateTime<Utc>>,
    pub items: BTreeMap<String, ManifestItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestItem {
    pub modify_time: String,
    pub remote_missing: bool,
    pub fields: Vec<ManifestField>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestField {
    pub qualified_name: String,
    pub path: String,
    pub ciphertext_sha256: String,
    pub retained_reason: Option<RetainedReason>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedReason {
    RemoteMissing,
    RemoteFieldMissing,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionJournal {
    pub schema_version: u32,
    pub stage_dir: PathBuf,
    pub next_manifest: PathBuf,
    pub operations: Vec<JournalOperation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalOperation {
    pub source: PathBuf,
    pub target: PathBuf,
    pub expected_before: Option<String>,
    pub expected_after: String,
}

pub struct StateLock {
    _file: File,
}

impl Manifest {
    #[must_use]
    pub fn empty(config: &Config) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            vault_share_id: config.vault_share_id.clone(),
            password_store_dir: config.password_store_dir.clone(),
            target_prefix: config.target_prefix.clone(),
            last_success_at: None,
            items: BTreeMap::new(),
        }
    }

    pub fn load(loaded: &LoadedConfig) -> Result<Self> {
        let path = manifest_path(&loaded.state_dir);
        if !path.exists() {
            return Ok(Self::empty(&loaded.config));
        }
        reject_symlink(&loaded.state_dir, "state directory")?;
        reject_symlink(&path, "manifest")?;
        let file = File::open(&path).context("cannot open state manifest")?;
        let manifest: Self = serde_json::from_reader(BufReader::new(file))
            .context("state manifest has an unsupported schema")?;
        manifest.validate(&loaded.config)?;
        Ok(manifest)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            bail!("unsupported state manifest version");
        }
        if self.vault_share_id != config.vault_share_id
            || self.password_store_dir != config.password_store_dir
            || self.target_prefix != config.target_prefix
        {
            bail!("state manifest belongs to a different synchronization configuration");
        }
        let fields = self.items.values().flat_map(|item| item.fields.iter());
        validate_path_graph(fields.clone().map(|field| field.path.as_str()))?;
        for field in fields {
            if field.ciphertext_sha256.len() != 64
                || !field
                    .ciphertext_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("state manifest contains an invalid ciphertext digest");
            }
        }
        Ok(())
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        atomic_write_json(&manifest_path(state_dir), self)
    }

    #[must_use]
    pub fn field_count(&self) -> usize {
        self.items.values().map(|item| item.fields.len()).sum()
    }

    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.items
            .values()
            .flat_map(|item| item.fields.iter())
            .filter(|field| field.retained_reason.is_some())
            .count()
    }
}

impl StateLock {
    pub fn acquire(state_dir: &Path) -> Result<Self> {
        ensure_state_dir(state_dir)?;
        let path = state_dir.join("sync.lock");
        reject_symlink_if_exists(&path, "state lock")?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path).context("cannot open state lock")?;
        set_owner_file_permissions(&path)?;
        file.try_lock_exclusive()
            .context("another proton-pass-sync process is already running")?;
        Ok(Self { _file: file })
    }
}

pub fn ensure_state_dir(state_dir: &Path) -> Result<()> {
    if state_dir.exists() {
        reject_symlink(state_dir, "state directory")?;
    }
    fs::create_dir_all(state_dir).context("cannot create state directory")?;
    #[cfg(unix)]
    fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
        .context("cannot secure state directory")?;
    Ok(())
}

#[must_use]
pub fn manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join("manifest.json")
}

#[must_use]
pub fn journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("transaction.json")
}

pub fn write_journal(state_dir: &Path, journal: &TransactionJournal) -> Result<()> {
    atomic_write_json(&journal_path(state_dir), journal)
}

pub fn load_journal(state_dir: &Path) -> Result<Option<TransactionJournal>> {
    let path = journal_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    reject_symlink(state_dir, "state directory")?;
    reject_symlink(&path, "transaction journal")?;
    let journal: TransactionJournal = serde_json::from_reader(BufReader::new(
        File::open(path).context("cannot open transaction journal")?,
    ))
    .context("transaction journal has an unsupported schema")?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION {
        bail!("unsupported transaction journal version");
    }
    Ok(Some(journal))
}

pub fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path).context("cannot open encrypted password-store entry")?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .context("cannot read encrypted password-store entry")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("state file has no parent")?;
    ensure_state_dir(parent)?;
    reject_symlink_if_exists(path, "state file")?;
    let mut temporary =
        NamedTempFile::new_in(parent).context("cannot create temporary state file")?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("cannot secure temporary state file")?;
    serde_json::to_writer_pretty(&mut temporary, value).context("cannot serialize state")?;
    temporary
        .write_all(b"\n")
        .context("cannot finish state file")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync state file")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("cannot atomically replace state file")?;
    set_owner_file_permissions(path)?;
    File::open(path)
        .context("cannot reopen state file")?
        .sync_all()
        .context("cannot sync published state file")?;
    sync_directory(parent)?;
    Ok(())
}

pub fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .context("cannot open directory for synchronization")?
        .sync_all()
        .context("cannot synchronize directory")
}

fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("cannot inspect {label}"))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} must not be a symbolic link");
    }
    Ok(())
}

fn reject_symlink_if_exists(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{label} must not be a symbolic link");
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {label}")),
    }
}

fn set_owner_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("cannot secure state file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(store: &Path) -> Config {
        Config {
            vault_share_id: "share".into(),
            password_store_dir: store.to_path_buf(),
            target_prefix: String::new(),
            proton_cli: "pass-cli".into(),
            pass_command: "pass".into(),
            gpg_command: "gpg".into(),
            stale_after_secs: 86_400,
        }
    }

    #[test]
    fn round_trips_manifest_with_owner_permissions() {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("state");
        let config = config(&temporary.path().join("store"));
        let manifest = Manifest::empty(&config);
        manifest.save(&state).unwrap();
        let loaded = LoadedConfig {
            config,
            config_path: temporary.path().join("config.toml"),
            state_dir: state.clone(),
        };
        Manifest::load(&loaded).unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(manifest_path(&state))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
