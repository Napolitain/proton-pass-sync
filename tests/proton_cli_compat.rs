#![cfg(unix)]

use proton_pass_sync::config::Config;
use proton_pass_sync::proton::ProtonClient;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn fake_proton_cli(version: &str, fixture_version: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("create fake CLI directory");
    let executable = directory.path().join("pass-cli");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_version);
    let script = format!(
        r#"#!/bin/sh
set -eu
case "${{1-}}" in
  --version)
    printf '%s\n' 'Proton Pass CLI {version} (fixture)'
    ;;
  info)
    [ "${{2-}}" = '--output' ]
    [ "${{3-}}" = 'json' ]
    printf '%s\n' '{{"session":"fixture-viewer-session"}}'
    ;;
  item)
    case "${{2-}}" in
      list)
        [ "$#" -eq 10 ]
        [ "${{3-}}" = '--share-id' ]
        [ "${{4-}}" = 'fixture-share' ]
        [ "${{5-}}" = '--filter-type' ]
        [ "${{6-}}" = 'custom' ]
        [ "${{7-}}" = '--filter-state' ]
        [ "${{8-}}" = 'active' ]
        [ "${{9-}}" = '--output' ]
        [ "${{10-}}" = 'json' ]
        cat {fixtures}/item-list.json
        ;;
      view)
        [ "$#" -eq 8 ]
        [ "${{3-}}" = '--share-id' ]
        [ "${{4-}}" = 'fixture-share' ]
        [ "${{5-}}" = '--item-id' ]
        [ -n "${{6-}}" ]
        [ "${{7-}}" = '--output' ]
        [ "${{8-}}" = 'json' ]
        cat {fixtures}/item-view-custom.json
        ;;
      *) exit 64 ;;
    esac
    ;;
  *) exit 64 ;;
esac
"#,
        fixtures = shell_quote(&fixtures),
    );
    fs::write(&executable, script).expect("write fake CLI");
    let mut permissions = fs::metadata(&executable)
        .expect("stat fake CLI")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).expect("make fake CLI executable");
    (directory, executable)
}

fn config(proton_cli: PathBuf) -> Config {
    Config {
        vault_share_id: "fixture-share".into(),
        password_store_dir: PathBuf::from("/tmp/fixture-password-store"),
        target_prefix: "coding".into(),
        proton_cli,
        pass_command: PathBuf::from("pass"),
        gpg_command: PathBuf::from("gpg"),
        stale_after_secs: 86_400,
    }
}

#[test]
fn pass_cli_222_inventory_and_custom_item_are_supported() {
    let (_directory, executable) = fake_proton_cli("2.2.2", "2.2.2");
    let config = config(executable);
    let client = ProtonClient::new(&config);

    assert_eq!(
        client.version().expect("supported version").to_string(),
        "2.2.2"
    );
    client.verify_session().expect("fixture session is valid");

    let inventory = client.inventory().expect("parse 2.2.2 inventory");
    assert_eq!(inventory.items.len(), 1);
    let item = client
        .view_custom_item(&inventory.items[0])
        .expect("parse 2.2.2 custom item");

    let paths: Vec<&str> = item
        .fields
        .iter()
        .map(|field| field.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "coding/compiler-service/production/token",
            "coding/compiler-service/production/endpoint",
            "coding/compiler-service/staging/token",
        ]
    );
    assert_eq!(
        item.fields[0].value.as_bytes(),
        b"fixture-hidden-value-alpha"
    );
}

#[test]
fn pass_cli_225_inventory_and_custom_item_are_supported() {
    let (_directory, executable) = fake_proton_cli("2.2.5", "2.2.5");
    let config = config(executable);
    let client = ProtonClient::new(&config);

    assert_eq!(
        client.version().expect("supported version").to_string(),
        "2.2.5"
    );
    let inventory = client.inventory().expect("parse 2.2.5 inventory");
    let item = client
        .view_custom_item(&inventory.items[0])
        .expect("parse 2.2.5 custom item");

    let paths: Vec<&str> = item
        .fields
        .iter()
        .map(|field| field.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "coding/release-bot/registry/username",
            "coding/release-bot/registry/credential",
        ]
    );
}

#[test]
fn pass_cli_outside_the_v1_compatibility_window_is_rejected() {
    for version in ["2.2.1", "3.0.0"] {
        let (_directory, executable) = fake_proton_cli(version, "2.2.5");
        let config = config(executable);
        let error = ProtonClient::new(&config)
            .version()
            .expect_err("unsupported version must fail closed");
        assert!(
            error.to_string().contains("unsupported Proton CLI version"),
            "unexpected error for {version}: {error:#}"
        );
    }
}
