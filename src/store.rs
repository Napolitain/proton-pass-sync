use crate::config::{Config, LoadedConfig};
use crate::manifest::{
    atomic_write_json, hash_file, journal_path, load_journal, manifest_path, sync_directory,
    write_journal, JournalOperation, Manifest, TransactionJournal, JOURNAL_SCHEMA_VERSION,
};
use crate::paths::{ciphertext_path, ensure_no_symlinks, validate_pass_path};
use crate::process::run_checked;
use crate::proton::CREDENTIAL_ENVIRONMENT;
use anyhow::{bail, Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};
use walkdir::WalkDir;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct StagedCiphertext {
    pub path: String,
    pub source: PathBuf,
    pub sha256: String,
}

pub struct StagingArea<'a> {
    config: &'a Config,
    directory: Option<TempDir>,
}

impl<'a> StagingArea<'a> {
    /// Stage already encrypted bytes. No recipient lookup or subprocess occurs.
    pub fn stage_ciphertext(&self, path: &str, bytes: &[u8]) -> Result<StagedCiphertext> {
        let path = validate_pass_path(path)?;
        let root = self
            .directory
            .as_ref()
            .context("staging already committed")?
            .path();
        let source = ciphertext_path(root, &path)?;
        let parent = source.parent().context("missing ciphertext parent")?;
        fs::create_dir_all(parent)?;
        fs::write(&source, bytes)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
        fs::File::open(&source)?.sync_all()?;
        sync_directory(parent)?;
        let sha256 = hash_file(&source)?;
        Ok(StagedCiphertext {
            path,
            source,
            sha256,
        })
    }

    pub fn new(config: &'a Config) -> Result<Self> {
        let directory = Builder::new()
            .prefix(".proton-pass-sync-stage-")
            .tempdir_in(&config.password_store_dir)
            .context("cannot create encrypted staging directory")?;
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .context("cannot secure encrypted staging directory")?;
        Ok(Self {
            config,
            directory: Some(directory),
        })
    }

    pub fn stage(&self, path: &str, plaintext: &[u8]) -> Result<StagedCiphertext> {
        let path = validate_pass_path(path)?;
        let stage_root = self
            .directory
            .as_ref()
            .context("staging directory was already committed")?
            .path();
        copy_applicable_gpg_ids(&self.config.password_store_dir, stage_root, &path)?;

        let args = vec![
            OsString::from("insert"),
            OsString::from("--force"),
            OsString::from("--multiline"),
            OsString::from("--"),
            OsString::from(&path),
        ];
        let environment = vec![
            (
                OsString::from("PASSWORD_STORE_DIR"),
                stage_root.as_os_str().to_os_string(),
            ),
            (
                OsString::from("PASSWORD_STORE_UMASK"),
                OsString::from("077"),
            ),
        ];
        let mut output = run_checked(
            &self.config.pass_command,
            &args,
            Some(plaintext),
            &environment,
            CREDENTIAL_ENVIRONMENT,
            "GNU pass encryption failed",
        )?;
        output.zeroize();

        let source = ciphertext_path(stage_root, &path)?;
        ensure_no_symlinks(stage_root, &source)?;
        let metadata = fs::metadata(&source).context("GNU pass did not create ciphertext")?;
        if !metadata.is_file() || metadata.len() == 0 {
            bail!("GNU pass produced invalid ciphertext");
        }
        fs::File::open(&source)
            .context("cannot reopen staged ciphertext")?
            .sync_all()
            .context("cannot synchronize staged ciphertext")?;
        validate_encrypted_packet(self.config, &source)?;
        sync_directory(source.parent().context("staged ciphertext has no parent")?)?;
        let sha256 = hash_file(&source)?;
        Ok(StagedCiphertext {
            path,
            source,
            sha256,
        })
    }

    pub fn keep(mut self) -> Result<PathBuf> {
        Ok(self
            .directory
            .take()
            .context("staging directory was already committed")?
            .into_path())
    }
}

pub fn verify_store(config: &Config) -> Result<()> {
    let metadata = fs::symlink_metadata(&config.password_store_dir)
        .context("GNU pass store is not initialized")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("GNU pass store must be a real directory, not a symbolic link");
    }
    refuse_git_store(&config.password_store_dir)?;

    let recipient_file = find_recipient_file_for_directory(
        &config.password_store_dir,
        Path::new(&config.target_prefix),
    )
    .context("GNU pass store has no applicable .gpg-id")?;
    ensure_no_symlinks(&config.password_store_dir, &recipient_file)?;
    let recipients = read_recipients(&recipient_file)?;
    if recipients.is_empty() {
        bail!("applicable GNU pass .gpg-id has no recipients");
    }

    let mut pass_output = run_checked(
        &config.pass_command,
        &[OsString::from("--version")],
        None,
        &[],
        CREDENTIAL_ENVIRONMENT,
        "GNU pass version check failed",
    )?;
    pass_output.zeroize();

    let mut gpg_output = run_checked(
        &config.gpg_command,
        &[OsString::from("--version")],
        None,
        &[],
        CREDENTIAL_ENVIRONMENT,
        "GPG version check failed",
    )?;
    gpg_output.zeroize();

    let mut args = vec![
        OsString::from("--batch"),
        OsString::from("--list-keys"),
        OsString::from("--"),
    ];
    args.extend(recipients.iter().map(OsString::from));
    let mut key_output = run_checked(
        &config.gpg_command,
        &args,
        None,
        &[],
        CREDENTIAL_ENVIRONMENT,
        "GPG recipient validation failed",
    )?;
    key_output.zeroize();
    Ok(())
}

pub fn refuse_git_store(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.context("cannot inspect GNU pass store")?;
        if entry.file_name() == OsStr::new(".git") {
            bail!("Git-backed GNU pass stores are not supported in v0.1");
        }
    }
    Ok(())
}

pub fn current_hash(config: &Config, path: &str) -> Result<Option<String>> {
    let target = ciphertext_path(&config.password_store_dir, path)?;
    ensure_no_symlinks(&config.password_store_dir, &target)?;
    match fs::metadata(&target) {
        Ok(metadata) if metadata.is_file() => hash_file(&target).map(Some),
        Ok(_) => bail!("managed password-store target is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("cannot inspect password-store target"),
    }
}

pub fn commit_transaction(
    loaded: &LoadedConfig,
    staging: StagingArea<'_>,
    staged: &[StagedCiphertext],
    expected_before: &[Option<String>],
    next_manifest: &Manifest,
) -> Result<()> {
    if staged.len() != expected_before.len() {
        bail!("internal transaction operation mismatch");
    }
    if staged.is_empty() {
        return next_manifest.save(&loaded.state_dir);
    }

    let stage_dir = staging.keep()?;
    let next_manifest_path = loaded.state_dir.join("manifest.next.json");
    if let Err(error) = atomic_write_json(&next_manifest_path, next_manifest) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(error);
    }
    let operations = staged
        .iter()
        .zip(expected_before)
        .map(|(field, before)| {
            Ok(JournalOperation {
                source: field.source.clone(),
                target: ciphertext_path(&loaded.config.password_store_dir, &field.path)?,
                expected_before: before.clone(),
                expected_after: field.sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let journal = TransactionJournal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        stage_dir,
        next_manifest: next_manifest_path,
        operations,
    };
    if let Err(error) = write_journal(&loaded.state_dir, &journal) {
        let _ = fs::remove_file(&journal.next_manifest);
        let _ = fs::remove_dir_all(&journal.stage_dir);
        return Err(error);
    }
    apply_journal(loaded, &journal)
}

pub fn recover_transaction(loaded: &LoadedConfig) -> Result<bool> {
    let Some(journal) = load_journal(&loaded.state_dir)? else {
        return Ok(false);
    };
    apply_journal(loaded, &journal)?;
    Ok(true)
}

fn apply_journal(loaded: &LoadedConfig, journal: &TransactionJournal) -> Result<()> {
    validate_journal_paths(loaded, journal)?;
    for operation in &journal.operations {
        ensure_no_symlinks(&journal.stage_dir, &operation.source)?;
        ensure_no_symlinks(&loaded.config.password_store_dir, &operation.target)?;
        if operation.source.exists() {
            let source_metadata = fs::metadata(&operation.source)
                .context("cannot inspect staged transaction ciphertext")?;
            if !source_metadata.is_file()
                || hash_file(&operation.source)? != operation.expected_after
            {
                bail!("staged transaction ciphertext failed integrity validation");
            }
            let current = hash_optional(&operation.target)?;
            if current != operation.expected_before {
                bail!("local ciphertext changed while recovering a transaction");
            }
            let parent = operation
                .target
                .parent()
                .context("managed target has no parent")?;
            create_secure_directories(&loaded.config.password_store_dir, parent)?;
            fs::rename(&operation.source, &operation.target)
                .context("cannot atomically install encrypted entry")?;
            fs::File::open(&operation.target)
                .context("cannot reopen installed ciphertext")?
                .sync_all()
                .context("cannot synchronize installed ciphertext")?;
            sync_directory(parent)?;
        }
        if hash_optional(&operation.target)?.as_deref() != Some(&operation.expected_after) {
            bail!("transaction recovery could not validate installed ciphertext");
        }
    }

    if journal.next_manifest.exists() {
        let file = fs::File::open(&journal.next_manifest).context("next manifest is unreadable")?;
        let next: Manifest = serde_json::from_reader(file).context("next manifest is invalid")?;
        next.validate(&loaded.config)?;
        fs::rename(&journal.next_manifest, manifest_path(&loaded.state_dir))
            .context("cannot publish transaction manifest")?;
        #[cfg(unix)]
        fs::set_permissions(
            manifest_path(&loaded.state_dir),
            fs::Permissions::from_mode(0o600),
        )
        .context("cannot secure transaction manifest")?;
        fs::File::open(manifest_path(&loaded.state_dir))
            .context("cannot reopen transaction manifest")?
            .sync_all()
            .context("cannot synchronize transaction manifest")?;
        sync_directory(&loaded.state_dir)?;
    } else {
        let current = Manifest::load(loaded)?;
        for operation in &journal.operations {
            let published = current
                .items
                .values()
                .flat_map(|item| &item.fields)
                .any(|field| {
                    ciphertext_path(&loaded.config.password_store_dir, &field.path)
                        .is_ok_and(|path| path == operation.target)
                        && field.ciphertext_sha256 == operation.expected_after
                });
            if !published {
                bail!("transaction manifest publication could not be verified");
            }
        }
    }
    if journal.stage_dir.exists() {
        ensure_no_symlinks(&loaded.config.password_store_dir, &journal.stage_dir)?;
        fs::remove_dir_all(&journal.stage_dir)
            .context("cannot clear encrypted staging directory")?;
        sync_directory(
            journal
                .stage_dir
                .parent()
                .context("staging directory has no parent")?,
        )?;
    }
    fs::remove_file(journal_path(&loaded.state_dir)).context("cannot clear transaction journal")?;
    sync_directory(&loaded.state_dir)?;
    Ok(())
}

fn validate_journal_paths(loaded: &LoadedConfig, journal: &TransactionJournal) -> Result<()> {
    if journal.stage_dir.parent() != Some(loaded.config.password_store_dir.as_path())
        || !is_clean_absolute_path(&journal.stage_dir)
        || !journal.stage_dir.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .starts_with(".proton-pass-sync-stage-")
        })
        || journal.next_manifest != loaded.state_dir.join("manifest.next.json")
        || !is_clean_absolute_path(&journal.next_manifest)
    {
        bail!("transaction journal contains unsafe paths");
    }
    for operation in &journal.operations {
        if !operation.source.starts_with(&journal.stage_dir)
            || !operation
                .target
                .starts_with(&loaded.config.password_store_dir)
            || operation.target.starts_with(&journal.stage_dir)
            || !is_clean_absolute_path(&operation.source)
            || !is_clean_absolute_path(&operation.target)
        {
            bail!("transaction journal operation escaped a managed directory");
        }
        let relative = operation
            .target
            .strip_prefix(&loaded.config.password_store_dir)
            .context("transaction target escaped password store")?;
        if operation.source != journal.stage_dir.join(relative) {
            bail!("transaction journal source and target do not correspond");
        }
    }
    Ok(())
}

fn copy_applicable_gpg_ids(store: &Path, stage: &Path, path: &str) -> Result<()> {
    let components: Vec<&str> = path.split('/').collect();
    for depth in 0..components.len() {
        let relative = components[..depth].iter().collect::<PathBuf>();
        let source = store.join(&relative).join(".gpg-id");
        match fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("applicable .gpg-id must be a regular file");
            }
            Ok(_) => {
                ensure_no_symlinks(store, &source)?;
                let destination_parent = stage.join(&relative);
                create_secure_directories(stage, &destination_parent)?;
                fs::copy(&source, destination_parent.join(".gpg-id"))
                    .context("cannot copy applicable GPG recipients into staging")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot inspect applicable .gpg-id"),
        }
    }
    if find_recipient_file_for_entry(stage, path).is_none() {
        bail!("no applicable GPG recipients for password-store entry");
    }
    Ok(())
}

fn find_recipient_file_for_entry(root: &Path, pass_path: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::from(pass_path);
    relative.pop();
    find_recipient_file_for_directory(root, &relative)
}

fn find_recipient_file_for_directory(root: &Path, relative: &Path) -> Option<PathBuf> {
    let mut current = root.join(relative);
    loop {
        let candidate = current.join(".gpg-id");
        if candidate.is_file() {
            return Some(candidate);
        }
        if current == root || !current.pop() || !current.starts_with(root) {
            return None;
        }
    }
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

fn read_recipients(path: &Path) -> Result<Vec<String>> {
    let source = fs::read_to_string(path).context("cannot read applicable .gpg-id")?;
    Ok(source
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn validate_encrypted_packet(config: &Config, path: &Path) -> Result<()> {
    let packet_home = Builder::new()
        .prefix(".proton-pass-sync-gpg-")
        .tempdir_in(path.parent().context("staged ciphertext has no parent")?)
        .context("cannot create isolated GPG packet-validation home")?;
    #[cfg(unix)]
    fs::set_permissions(packet_home.path(), fs::Permissions::from_mode(0o700))
        .context("cannot secure isolated GPG packet-validation home")?;
    let args = vec![
        OsString::from("--no-options"),
        OsString::from("--homedir"),
        packet_home.path().as_os_str().to_os_string(),
        OsString::from("--batch"),
        OsString::from("--list-only"),
        OsString::from("--list-packets"),
        OsString::from("--"),
        path.as_os_str().to_os_string(),
    ];
    let mut output = run_checked(
        &config.gpg_command,
        &args,
        None,
        &[],
        CREDENTIAL_ENVIRONMENT,
        "staged GPG packet validation failed",
    )?;
    output.zeroize();
    Ok(())
}

fn create_secure_directories(root: &Path, target: &Path) -> Result<()> {
    if !target.starts_with(root) {
        bail!("directory creation escaped its managed root");
    }
    ensure_no_symlinks(root, target)?;
    fs::create_dir_all(target).context("cannot create managed directory")?;
    #[cfg(unix)]
    {
        let relative = target
            .strip_prefix(root)
            .context("managed directory escaped root")?;
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component);
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                .context("cannot secure managed directory")?;
        }
    }
    Ok(())
}

fn hash_optional(path: &Path) -> Result<Option<String>> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => hash_file(path).map(Some),
        Ok(_) => bail!("transaction target is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("cannot inspect transaction target"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nearest_recipient_file() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join(".gpg-id"), "root\n").unwrap();
        fs::create_dir(temporary.path().join("team")).unwrap();
        fs::write(temporary.path().join("team/.gpg-id"), "team\n").unwrap();
        assert_eq!(
            find_recipient_file_for_entry(temporary.path(), "team/item/field").unwrap(),
            temporary.path().join("team/.gpg-id")
        );
    }

    #[test]
    fn parses_recipient_comments_and_blanks() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(".gpg-id");
        fs::write(&path, "alice # primary\n\n bob\n").unwrap();
        assert_eq!(read_recipients(&path).unwrap(), ["alice", "bob"]);
    }
}
