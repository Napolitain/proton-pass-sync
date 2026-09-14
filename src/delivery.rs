//! Ciphertext-only transfer across the producer/desktop UID boundary.
use crate::config::LoadedConfig;
use crate::manifest::{
    sync_directory, Manifest, ManifestField, ManifestItem, RetainedReason, StateLock,
};
use crate::paths::{ciphertext_path, ensure_no_symlinks, validate_path_graph};
use crate::store::{
    commit_transaction, current_hash, recover_transaction, refuse_git_store, StagingArea,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    vault_share_id: String,
    target_prefix: String,
    last_source_success_at: chrono::DateTime<chrono::Utc>,
    items: Vec<Item>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    id: String,
    modify_time: String,
    remote_missing: bool,
    fields: Vec<Field>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    metadata: ManifestField,
    ciphertext_base64: String,
}

pub fn export(loaded: &LoadedConfig, output: &Path) -> Result<()> {
    let _lock = StateLock::acquire(&loaded.state_dir)?;
    recover_transaction(loaded)?;
    let manifest = Manifest::load(loaded)?;
    let mut items = Vec::new();
    for (id, item) in manifest.items {
        let mut fields = Vec::new();
        for metadata in item.fields {
            ensure!(
                current_hash(&loaded.config, &metadata.path)?.as_deref()
                    == Some(&metadata.ciphertext_sha256),
                "private mirror changed since synchronization"
            );
            let path = ciphertext_path(&loaded.config.password_store_dir, &metadata.path)?;
            let bytes = fs::read(path)?;
            fields.push(Field {
                metadata,
                ciphertext_base64: STANDARD.encode(bytes),
            });
        }
        items.push(Item {
            id,
            modify_time: item.modify_time,
            remote_missing: item.remote_missing,
            fields,
        });
    }
    let snapshot = Snapshot {
        schema_version: 1,
        vault_share_id: manifest.vault_share_id,
        target_prefix: manifest.target_prefix,
        last_source_success_at: manifest
            .last_success_at
            .context("mirror has never synchronized")?,
        items,
    };
    let bytes = serde_json::to_vec(&snapshot)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "ciphertext snapshot exceeds safety limit"
    );
    let parent = output
        .parent()
        .context("snapshot needs a parent directory")?;
    // The producer's parent directory must remain private. Only PID 1 projects
    // this readable file into the consumer's mount namespace.
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temporary.as_file().sync_all()?;
    temporary.persist(output).map_err(|e| e.error)?;
    sync_directory(parent)?;
    println!("ciphertext snapshot published");
    Ok(())
}

pub fn import(loaded: &LoadedConfig, input: &Path, dry_run: bool, accept: &[String]) -> Result<()> {
    ensure!(
        !dry_run || accept.is_empty(),
        "dry-run cannot accept conflicts"
    );
    // Open once: an atomic producer replacement must not mix generations.
    let file = File::open(input)?;
    ensure!(
        file.metadata()?.is_file(),
        "snapshot must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "ciphertext snapshot exceeds safety limit"
    );
    let snapshot: Snapshot = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid ciphertext snapshot"))?;
    ensure!(snapshot.schema_version == 1, "unsupported snapshot version");
    ensure!(
        snapshot.vault_share_id == loaded.config.vault_share_id
            && snapshot.target_prefix == loaded.config.target_prefix,
        "snapshot identity mismatch"
    );
    let mut next = Manifest::empty(&loaded.config);
    next.last_success_at = Some(snapshot.last_source_success_at);
    let mut ciphertext = BTreeMap::new();
    for item in snapshot.items {
        ensure!(
            !item.id.is_empty()
                && !item.modify_time.is_empty()
                && !next.items.contains_key(&item.id),
            "invalid or duplicate item identity"
        );
        let mut fields = Vec::new();
        for field in item.fields {
            let decoded = STANDARD
                .decode(&field.ciphertext_base64)
                .context("invalid ciphertext encoding")?;
            ensure!(
                !decoded.is_empty()
                    && format!("{:x}", Sha256::digest(&decoded))
                        == field.metadata.ciphertext_sha256,
                "ciphertext digest mismatch"
            );
            ensure!(
                ciphertext
                    .insert(field.metadata.path.clone(), decoded)
                    .is_none(),
                "duplicate ciphertext path"
            );
            fields.push(field.metadata);
        }
        next.items.insert(
            item.id,
            ManifestItem {
                modify_time: item.modify_time,
                remote_missing: item.remote_missing,
                fields,
            },
        );
    }
    next.validate(&loaded.config)?;
    let store = &loaded.config.password_store_dir;
    ensure!(
        fs::symlink_metadata(store)?.is_dir(),
        "destination must be a real directory"
    );
    refuse_git_store(store)?;
    let _lock = if dry_run {
        None
    } else {
        Some(StateLock::acquire(&loaded.state_dir)?)
    };
    if dry_run {
        ensure!(
            crate::manifest::load_journal(&loaded.state_dir)?.is_none(),
            "transaction needs recovery before dry-run"
        );
    } else {
        recover_transaction(loaded)?;
    }
    let previous = Manifest::load(loaded)?;
    let owned: BTreeMap<_, _> = previous
        .items
        .values()
        .flat_map(|i| i.fields.iter())
        .map(|f| (f.path.clone(), f.ciphertext_sha256.clone()))
        .collect();
    let mut before = BTreeMap::new();
    let mut conflicts = HashSet::new();
    for (path, hash) in &owned {
        let current = current_hash(&loaded.config, path)?;
        if current.as_ref() != Some(hash) {
            conflicts.insert(path.clone());
        }
        before.insert(path.clone(), current);
    }
    for path in ciphertext.keys() {
        if !owned.contains_key(path) {
            let current = current_hash(&loaded.config, path)?;
            if current.is_some() {
                conflicts.insert(path.clone());
            }
            before.insert(path.clone(), current);
        }
    }
    let accepted: HashSet<_> = accept.iter().cloned().collect();
    ensure!(accepted.len() == accept.len(), "duplicate accepted path");
    if dry_run {
        println!(
            "import dry-run: entries={} conflicts={}",
            ciphertext.len(),
            conflicts.len()
        );
        return Ok(());
    }
    ensure!(
        conflicts == accepted && accepted.iter().all(|p| ciphertext.contains_key(p)),
        "local conflicts require exact --accept-remote paths"
    );
    // A producer may have explicitly pruned an entry. Delivery still never deletes.
    for (id, item) in previous.items {
        for mut field in item.fields {
            if !ciphertext.contains_key(&field.path) {
                field.retained_reason = Some(RetainedReason::RemoteMissing);
                next.items
                    .entry(id.clone())
                    .or_insert_with(|| ManifestItem {
                        modify_time: item.modify_time.clone(),
                        remote_missing: true,
                        fields: Vec::new(),
                    })
                    .fields
                    .push(field);
            }
        }
    }
    validate_path_graph(
        next.items
            .values()
            .flat_map(|i| i.fields.iter().map(|f| f.path.as_str())),
    )?;
    next.validate(&loaded.config)?;
    let staging = StagingArea::new(&loaded.config)?;
    let mut staged = Vec::new();
    let mut expected = Vec::new();
    for (path, bytes) in ciphertext {
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if before[&path].as_ref() == Some(&digest) {
            continue;
        }
        ensure_no_symlinks(store, &ciphertext_path(store, &path)?)?;
        staged.push(staging.stage_ciphertext(&path, &bytes)?);
        expected.push(before.remove(&path).context("missing preflight")?);
    }
    // Mark consumer state before committing so prune can never resurrect data.
    fs::write(loaded.state_dir.join("ciphertext-consumer"), b"1\n")?;
    commit_transaction(loaded, staging, &staged, &expected, &next)?;
    println!(
        "ciphertext import complete: updated_entries={}",
        staged.len()
    );
    Ok(())
}
