use crate::config::LoadedConfig;
use crate::manifest::{
    load_journal, Manifest, ManifestField, ManifestItem, RetainedReason, StateLock,
};
use crate::paths::{ciphertext_path, ensure_no_symlinks, validate_pass_path, validate_path_graph};
use crate::proton::{ItemSummary, ProtonClient, RemoteField};
use crate::store::{
    commit_transaction, current_hash, recover_transaction, refuse_git_store, verify_store,
    StagingArea,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::time::SystemTime;

pub fn doctor(loaded: &LoadedConfig) -> Result<()> {
    let proton = ProtonClient::new(&loaded.config);
    let version = proton.version()?;
    proton.verify_session()?;
    let inventory = proton.inventory()?;
    verify_store(&loaded.config)?;
    println!(
        "ok: Proton CLI {version}; active custom items={}; GNU pass store ready",
        inventory.items.len()
    );
    Ok(())
}

pub fn synchronize(
    loaded: &LoadedConfig,
    dry_run: bool,
    full: bool,
    accept_remote: &[String],
) -> Result<()> {
    let _lock = if dry_run {
        None
    } else {
        Some(StateLock::acquire(&loaded.state_dir)?)
    };
    if dry_run && load_journal(&loaded.state_dir)?.is_some() {
        bail!("a transaction requires recovery; run sync without --dry-run");
    }
    if dry_run && !accept_remote.is_empty() {
        bail!("--accept-remote cannot be combined with --dry-run");
    }
    if !dry_run {
        recover_transaction(loaded)?;
    }

    verify_store(&loaded.config)?;
    let proton = ProtonClient::new(&loaded.config);
    proton.version()?;
    proton.verify_session()?;
    let inventory = proton.inventory()?;
    let manifest = Manifest::load(loaded)?;
    let inventory_by_id: BTreeMap<String, ItemSummary> = inventory
        .items
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();

    let local = inspect_manifest(&loaded.config, &manifest)?;
    let known_conflicts: HashSet<String> = manifest
        .items
        .values()
        .flat_map(|item| item.fields.iter())
        .filter(|field| local.get(&field.path) != Some(&Some(field.ciphertext_sha256.clone())))
        .map(|field| field.path.clone())
        .collect();
    let changed_ids = changed_item_ids(&manifest, &inventory_by_id, full);
    let remote_missing_items = manifest
        .items
        .keys()
        .filter(|id| !inventory_by_id.contains_key(*id))
        .count();

    if dry_run {
        println!(
            "dry-run: changed_items={} remote_missing_items={} local_conflicts={} unresolved_items={}",
            changed_ids.len(),
            remote_missing_items,
            known_conflicts.len(),
            changed_ids.len()
        );
        return Ok(());
    }

    let accepted = parse_accepted_paths(accept_remote)?;
    let mut fetch_ids = changed_ids;
    for (item_id, item) in &manifest.items {
        if item
            .fields
            .iter()
            .any(|field| accepted.contains(&field.path))
            && inventory_by_id.contains_key(item_id)
        {
            fetch_ids.insert(item_id.clone());
        }
    }

    let mut remote_items = Vec::with_capacity(fetch_ids.len());
    for item_id in &fetch_ids {
        let summary = inventory_by_id
            .get(item_id)
            .context("remote item disappeared during synchronization")?;
        remote_items.push(proton.view_custom_item(summary)?);
    }

    let owned: HashMap<String, String> = manifest
        .items
        .values()
        .flat_map(|item| item.fields.iter())
        .map(|field| (field.path.clone(), field.ciphertext_sha256.clone()))
        .collect();
    let mut next = manifest.clone();
    mark_remote_missing(&mut next, &inventory_by_id);
    let mut pending = Vec::new();

    for remote in remote_items {
        let old_fields = manifest
            .items
            .get(&remote.id)
            .map(|item| item.fields.clone())
            .unwrap_or_default();
        let active_paths: HashSet<&str> = remote
            .fields
            .iter()
            .map(|field| field.path.as_str())
            .collect();
        let mut retained = Vec::new();
        for mut old in old_fields {
            if active_paths.contains(old.path.as_str()) {
                continue;
            }
            old.retained_reason = Some(RetainedReason::RemoteFieldMissing);
            retained.push(old);
        }
        next.items.insert(
            remote.id.clone(),
            ManifestItem {
                modify_time: remote.modify_time,
                remote_missing: false,
                fields: retained,
            },
        );
        for field in remote.fields {
            pending.push(PendingField {
                item_id: remote.id.clone(),
                field,
            });
        }
    }

    let mut desired_paths: Vec<&str> = next
        .items
        .values()
        .flat_map(|item| item.fields.iter().map(|field| field.path.as_str()))
        .collect();
    desired_paths.extend(pending.iter().map(|field| field.field.path.as_str()));
    validate_path_graph(desired_paths)?;

    let pending_paths: HashSet<&str> = pending
        .iter()
        .map(|field| field.field.path.as_str())
        .collect();
    for conflict in &known_conflicts {
        if !pending_paths.contains(conflict.as_str()) || !accepted.contains(conflict) {
            bail!("local password-store conflicts must be resolved or explicitly accepted");
        }
    }

    let mut actual_conflicts = known_conflicts;
    let mut current_for_pending = HashMap::new();
    for pending_field in &pending {
        let path = &pending_field.field.path;
        let current = if let Some(value) = local.get(path) {
            value.clone()
        } else {
            current_hash(&loaded.config, path)?
        };
        if !owned.contains_key(path) && current.is_some() {
            actual_conflicts.insert(path.clone());
        }
        current_for_pending.insert(path.clone(), current);
    }
    for conflict in &actual_conflicts {
        if !pending_paths.contains(conflict.as_str()) || !accepted.contains(conflict) {
            bail!("unmanaged or locally modified password-store targets require --accept-remote");
        }
    }
    if accepted != actual_conflicts {
        bail!("--accept-remote included a path that is not an active conflict");
    }

    let staging = StagingArea::new(&loaded.config)?;
    let mut staged = Vec::with_capacity(pending.len());
    let mut expected_before = Vec::with_capacity(pending.len());
    for pending_field in pending {
        let encrypted = staging.stage(
            &pending_field.field.path,
            pending_field.field.value.as_bytes(),
        )?;
        expected_before.push(
            current_for_pending
                .remove(&pending_field.field.path)
                .context("missing local preflight result")?,
        );
        next.items
            .get_mut(&pending_field.item_id)
            .context("missing prepared manifest item")?
            .fields
            .push(ManifestField {
                qualified_name: pending_field.field.qualified_name,
                path: pending_field.field.path,
                ciphertext_sha256: encrypted.sha256.clone(),
                retained_reason: None,
            });
        staged.push(encrypted);
    }
    next.last_success_at = Some(now_utc());
    next.validate(&loaded.config)?;
    let updated_entries = staged.len();
    commit_transaction(loaded, staging, &staged, &expected_before, &next)?;
    println!(
        "sync complete: updated_entries={updated_entries} retained_entries={} remote_missing_items={remote_missing_items}",
        next.retained_count()
    );
    Ok(())
}

pub fn status(loaded: &LoadedConfig, json: bool) -> Result<()> {
    let manifest = Manifest::load(loaded)?;
    let local = inspect_manifest(&loaded.config, &manifest)?;
    let conflicts = manifest
        .items
        .values()
        .flat_map(|item| item.fields.iter())
        .filter(|field| local.get(&field.path) != Some(&Some(field.ciphertext_sha256.clone())))
        .count();
    let age = manifest.last_success_at.map(|time| {
        u64::try_from(now_utc().signed_duration_since(time).num_seconds().max(0)).unwrap_or(0)
    });
    let report = StatusReport {
        schema_version: 1,
        last_success_at: manifest.last_success_at,
        cache_age_seconds: age,
        stale: age.map_or(true, |seconds| seconds > loaded.config.stale_after_secs),
        items: manifest.items.len(),
        entries: manifest.field_count(),
        conflicts,
        retained_entries: manifest.retained_count(),
        remote_missing_items: manifest
            .items
            .values()
            .filter(|item| item.remote_missing)
            .count(),
        pending_transaction: load_journal(&loaded.state_dir)?.is_some(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "status: entries={} conflicts={} retained={} stale={} pending_transaction={}",
            report.entries,
            report.conflicts,
            report.retained_entries,
            report.stale,
            report.pending_transaction
        );
    }
    Ok(())
}

pub fn prune(loaded: &LoadedConfig, path: &str) -> Result<()> {
    let _lock = StateLock::acquire(&loaded.state_dir)?;
    recover_transaction(loaded)?;
    refuse_git_store(&loaded.config.password_store_dir)?;
    let path = validate_pass_path(path)?;
    let mut manifest = Manifest::load(loaded)?;
    let (item_id, expected_hash) = manifest
        .items
        .iter()
        .find_map(|(item_id, item)| {
            item.fields
                .iter()
                .find(|field| field.path == path && field.retained_reason.is_some())
                .map(|field| (item_id.clone(), field.ciphertext_sha256.clone()))
        })
        .context("the requested path is not a retained manifest entry")?;
    if current_hash(&loaded.config, &path)?.as_deref() != Some(&expected_hash) {
        bail!("retained entry was locally modified or deleted; refusing to prune");
    }

    print!("Permanently delete this retained encrypted entry? [y/N] ");
    io::stdout()
        .flush()
        .context("cannot write confirmation prompt")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("cannot read confirmation")?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("prune cancelled");
    }

    let target = ciphertext_path(&loaded.config.password_store_dir, &path)?;
    ensure_no_symlinks(&loaded.config.password_store_dir, &target)?;
    let tombstone = target.with_extension("gpg.proton-pass-sync-prune");
    if tombstone.exists() {
        bail!("a prior prune tombstone already exists");
    }
    fs::rename(&target, &tombstone).context("cannot stage retained entry deletion")?;
    crate::manifest::sync_directory(target.parent().context("retained entry has no parent")?)?;
    let item = manifest
        .items
        .get_mut(&item_id)
        .context("retained item disappeared from manifest")?;
    item.fields.retain(|field| field.path != path);
    if item.fields.is_empty() {
        manifest.items.remove(&item_id);
    }
    if let Err(error) = manifest.save(&loaded.state_dir) {
        let _ = fs::rename(&tombstone, &target);
        return Err(error);
    }
    fs::remove_file(&tombstone).context("cannot finish retained entry deletion")?;
    crate::manifest::sync_directory(target.parent().context("retained entry has no parent")?)?;
    println!("prune complete: removed_entries=1");
    Ok(())
}

struct PendingField {
    item_id: String,
    field: RemoteField,
}

#[derive(Serialize)]
struct StatusReport {
    schema_version: u32,
    last_success_at: Option<chrono::DateTime<Utc>>,
    cache_age_seconds: Option<u64>,
    stale: bool,
    items: usize,
    entries: usize,
    conflicts: usize,
    retained_entries: usize,
    remote_missing_items: usize,
    pending_transaction: bool,
}

fn changed_item_ids(
    manifest: &Manifest,
    inventory: &BTreeMap<String, ItemSummary>,
    full: bool,
) -> HashSet<String> {
    inventory
        .iter()
        .filter(|(id, summary)| {
            full || manifest.items.get(*id).map_or(true, |item| {
                item.remote_missing || item.modify_time != summary.modify_time
            })
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn mark_remote_missing(manifest: &mut Manifest, inventory: &BTreeMap<String, ItemSummary>) {
    for (item_id, item) in &mut manifest.items {
        if !inventory.contains_key(item_id) {
            item.remote_missing = true;
            for field in &mut item.fields {
                field.retained_reason = Some(RetainedReason::RemoteMissing);
            }
        }
    }
}

fn inspect_manifest(
    config: &crate::config::Config,
    manifest: &Manifest,
) -> Result<HashMap<String, Option<String>>> {
    manifest
        .items
        .values()
        .flat_map(|item| item.fields.iter())
        .map(|field| Ok((field.path.clone(), current_hash(config, &field.path)?)))
        .collect()
}

fn parse_accepted_paths(paths: &[String]) -> Result<HashSet<String>> {
    let mut accepted = HashSet::new();
    for path in paths {
        let path = validate_pass_path(path)?;
        if !accepted.insert(path) {
            bail!("--accept-remote path was supplied more than once");
        }
    }
    Ok(accepted)
}

fn now_utc() -> chrono::DateTime<Utc> {
    SystemTime::now().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn manifest() -> Manifest {
        let config = Config {
            vault_share_id: "share".into(),
            password_store_dir: PathBuf::from("/store"),
            target_prefix: String::new(),
            proton_cli: "pass-cli".into(),
            pass_command: "pass".into(),
            gpg_command: "gpg".into(),
            stale_after_secs: 86_400,
        };
        let mut manifest = Manifest::empty(&config);
        manifest.items.insert(
            "one".into(),
            ManifestItem {
                modify_time: "old".into(),
                remote_missing: false,
                fields: Vec::new(),
            },
        );
        manifest
    }

    #[test]
    fn incremental_diff_uses_modify_time() {
        let inventory = BTreeMap::from([
            (
                "one".into(),
                ItemSummary {
                    id: "one".into(),
                    modify_time: "new".into(),
                },
            ),
            (
                "two".into(),
                ItemSummary {
                    id: "two".into(),
                    modify_time: "now".into(),
                },
            ),
        ]);
        assert_eq!(changed_item_ids(&manifest(), &inventory, false).len(), 2);
    }

    #[test]
    fn remote_missing_items_are_retained() {
        let mut manifest = manifest();
        manifest
            .items
            .get_mut("one")
            .unwrap()
            .fields
            .push(ManifestField {
                qualified_name: "s.f".into(),
                path: "item/s/f".into(),
                ciphertext_sha256: "a".repeat(64),
                retained_reason: None,
            });
        mark_remote_missing(&mut manifest, &BTreeMap::new());
        let item = manifest.items.get("one").unwrap();
        assert!(item.remote_missing);
        assert_eq!(
            item.fields[0].retained_reason,
            Some(RetainedReason::RemoteMissing)
        );
    }
}
