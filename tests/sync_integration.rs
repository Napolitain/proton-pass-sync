#![cfg(unix)]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Harness {
    directory: tempfile::TempDir,
    config: PathBuf,
    log: PathBuf,
    state: PathBuf,
    store: PathBuf,
}

impl Harness {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create integration directory");
        let root = directory.path();
        let bin = root.join("bin");
        let home = root.join("home");
        let state = root.join("state");
        let store = root.join("password-store");
        let log = root.join("commands.log");
        fs::create_dir(&bin).expect("create fake command directory");
        fs::create_dir(&home).expect("create fake home");
        fs::create_dir(&state).expect("create fake state root");
        fs::create_dir(&store).expect("create fake password store");
        fs::write(store.join(".gpg-id"), "fixture-recipient\n")
            .expect("initialize fake password store");

        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/2.2.2");
        let proton_cli = bin.join("pass-cli");
        write_executable(
            &proton_cli,
            &format!(
                r#"#!/bin/sh
set -eu
[ -z "${{PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}}" ] || exit 97
printf 'proton %s\n' "$*" >> {log}
if [ "${{FIXTURE_PROTON_FAIL-}}" = 1 ]; then
  printf '%s\n' 'fixture-hidden-value-alpha' >&2
  exit 69
fi
case "${{1-}}" in
  --version)
    printf '%s\n' 'Proton Pass CLI 2.2.2 (fixture)'
    ;;
  info)
    [ "${{2-}}" = '--output' ]
    [ "${{3-}}" = 'json' ]
    printf '%s\n' '{{"session":"fixture-viewer-session"}}'
    ;;
  item)
    case "${{2-}}" in
      list)
        if [ "${{FIXTURE_EMPTY_INVENTORY-}}" = 1 ]; then
          printf '%s\n' '{{"items":[]}}'
        else
          cat {fixtures}/item-list.json
        fi
        ;;
      view)
        cat {fixtures}/item-view-custom.json
        ;;
      *) exit 64 ;;
    esac
    ;;
  *) exit 64 ;;
esac
"#,
                log = shell_quote(&log),
                fixtures = shell_quote(&fixtures),
            ),
        );

        let pass = bin.join("pass");
        write_executable(
            &pass,
            &format!(
                r#"#!/bin/sh
set -eu
[ -z "${{PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}}" ] || exit 97
printf 'pass %s\n' "$*" >> {log}
case "${{1-}}" in
  --version)
    printf '%s\n' 'pass fixture 1.7.4'
    ;;
  insert)
    [ "$#" -eq 5 ]
    [ "${{2-}}" = '--force' ]
    [ "${{3-}}" = '--multiline' ]
    [ "${{4-}}" = '--' ]
    destination="${{PASSWORD_STORE_DIR}}/${{5}}.gpg"
    mkdir -p "$(dirname "$destination")"
    cat >/dev/null
    printf 'fixture ciphertext for %s\n' "${{5}}" > "$destination"
    ;;
  *) exit 64 ;;
esac
"#,
                log = shell_quote(&log),
            ),
        );

        let gpg = bin.join("gpg");
        write_executable(
            &gpg,
            &format!(
                r#"#!/bin/sh
set -eu
[ -z "${{PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}}" ] || exit 97
printf 'gpg %s\n' "$*" >> {log}
case "${{1-}}" in
  --version) printf '%s\n' 'gpg fixture 2.4' ;;
  --batch) exit 0 ;;
  --no-options)
    [ "$#" -eq 8 ]
    [ "${{2-}}" = '--homedir' ]
    [ -d "${{3-}}" ]
    [ "${{4-}}" = '--batch' ]
    [ "${{5-}}" = '--list-only' ]
    [ "${{6-}}" = '--list-packets' ]
    [ "${{7-}}" = '--' ]
    [ -f "${{8-}}" ]
    exit 0
    ;;
  *) exit 64 ;;
esac
"#,
                log = shell_quote(&log),
            ),
        );

        let config = root.join("config.toml");
        fs::write(
            &config,
            format!(
                r#"schema_version = 1
vault_share_id = "fixture-share"
password_store_dir = "{}"
target_prefix = "coding"
proton_cli = "{}"
pass_command = "{}"
gpg_command = "{}"
stale_after_secs = 86400
"#,
                store.display(),
                proton_cli.display(),
                pass.display(),
                gpg.display(),
            ),
        )
        .expect("write integration configuration");

        Self {
            directory,
            config,
            log,
            state,
            store,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_proton-pass-sync"));
        command
            .env("HOME", self.directory.path().join("home"))
            .env("XDG_STATE_HOME", &self.state)
            .env(
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                "fixture-parent-only-credential",
            )
            .args(["--config", self.config.to_str().expect("UTF-8 path")]);
        command
    }

    fn manifest(&self) -> PathBuf {
        self.state.join("proton-pass-sync/manifest.json")
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fake executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake command executable");
}

fn synced_paths(store: &Path) -> [PathBuf; 3] {
    [
        store.join("coding/compiler-service/production/token.gpg"),
        store.join("coding/compiler-service/production/endpoint.gpg"),
        store.join("coding/compiler-service/staging/token.gpg"),
    ]
}

fn run_initial_sync(harness: &Harness) {
    harness
        .command()
        .arg("sync")
        .assert()
        .success()
        .stdout(predicate::str::contains("updated_entries=3"))
        .stdout(predicate::str::contains("compiler-service").not())
        .stderr(predicate::str::is_empty());
    for path in synced_paths(&harness.store) {
        assert!(
            path.is_file(),
            "missing synchronized ciphertext: {}",
            path.display()
        );
    }
}

#[test]
fn dry_run_is_secret_free_and_does_not_fetch_or_encrypt_items() {
    let harness = Harness::new();
    harness
        .command()
        .args(["sync", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("changed_items=1"))
        .stdout(predicate::str::contains("unresolved_items=1"))
        .stdout(predicate::str::contains("compiler-service").not())
        .stderr(predicate::str::is_empty());

    let commands = fs::read_to_string(&harness.log).expect("read fake command log");
    assert!(commands.contains("proton item list"));
    assert!(!commands.contains("proton item view"));
    assert!(!commands.contains("pass insert"));
    assert!(!harness.manifest().exists());
    assert!(!harness.state.join("proton-pass-sync").exists());
    assert!(synced_paths(&harness.store)
        .iter()
        .all(|path| !path.exists()));
}

#[test]
fn successful_sync_survives_outage_and_refuses_local_drift() {
    let harness = Harness::new();
    run_initial_sync(&harness);

    let manifest_before = fs::read(harness.manifest()).expect("read synchronized manifest");
    let ciphertext_before: Vec<Vec<u8>> = synced_paths(&harness.store)
        .iter()
        .map(|path| fs::read(path).expect("read synchronized ciphertext"))
        .collect();
    let manifest_text = String::from_utf8(manifest_before.clone()).expect("manifest is UTF-8");
    for secret in [
        "fixture-hidden-value-alpha",
        "fixture-hidden-value-beta",
        "https://fixture.invalid/api",
    ] {
        assert!(
            !manifest_text.contains(secret),
            "manifest leaked a fixture value"
        );
    }

    harness
        .command()
        .env("FIXTURE_PROTON_FAIL", "1")
        .arg("sync")
        .assert()
        .failure()
        .stderr(predicate::str::contains("fixture-hidden-value-alpha").not());
    assert_eq!(fs::read(harness.manifest()).unwrap(), manifest_before);
    for (path, expected) in synced_paths(&harness.store).iter().zip(&ciphertext_before) {
        assert_eq!(&fs::read(path).unwrap(), expected);
    }

    let drifted = synced_paths(&harness.store)[0].clone();
    fs::write(&drifted, "fixture local edit").expect("simulate local ciphertext drift");
    harness
        .command()
        .arg("sync")
        .assert()
        .failure()
        .stderr(predicate::str::contains("conflicts must be resolved"));
    assert_eq!(fs::read_to_string(drifted).unwrap(), "fixture local edit");
    assert_eq!(fs::read(harness.manifest()).unwrap(), manifest_before);
}

#[test]
fn remote_disappearance_is_retained_until_explicit_prune() {
    let harness = Harness::new();
    run_initial_sync(&harness);
    let ciphertext_before: Vec<Vec<u8>> = synced_paths(&harness.store)
        .iter()
        .map(|path| fs::read(path).expect("read synchronized ciphertext"))
        .collect();

    harness
        .command()
        .env("FIXTURE_EMPTY_INVENTORY", "1")
        .arg("sync")
        .assert()
        .success()
        .stdout(predicate::str::contains("remote_missing_items=1"));

    for (path, expected) in synced_paths(&harness.store).iter().zip(&ciphertext_before) {
        assert_eq!(&fs::read(path).unwrap(), expected);
    }
    let manifest: Value = serde_json::from_slice(&fs::read(harness.manifest()).unwrap()).unwrap();
    assert_eq!(
        manifest["items"]["fixture-item-custom-222"]["remote_missing"],
        true
    );
    assert_eq!(
        manifest["items"]["fixture-item-custom-222"]["fields"][0]["retained_reason"],
        "remote_missing"
    );
}
