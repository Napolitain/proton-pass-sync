use base64::{engine::general_purpose::STANDARD, Engine};
use proton_pass_sync::{
    config::{Config, LoadedConfig},
    delivery,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn config(root: &Path) -> LoadedConfig {
    fs::create_dir_all(root.join("store")).unwrap();
    LoadedConfig {
        config: Config {
            vault_share_id: "fake-vault".into(),
            password_store_dir: root.join("store"),
            target_prefix: String::new(),
            proton_cli: "/does-not-exist/proton".into(),
            pass_command: "/does-not-exist/pass".into(),
            gpg_command: "/does-not-exist/gpg".into(),
            stale_after_secs: 86400,
        },
        config_path: root.join("config.toml"),
        state_dir: root.join("state"),
    }
}

fn snapshot(entries: &[(&str, &[u8])]) -> Value {
    json!({"schema_version":1, "vault_share_id":"fake-vault", "target_prefix":"",
    "last_source_success_at":"2026-01-01T00:00:00Z", "items":[{
      "id":"fake-item", "modify_time":"first", "remote_missing":false,
      "fields":entries.iter().map(|(path, bytes)| json!({
        "metadata":{"qualified_name":path,"path":path,"ciphertext_sha256":format!("{:x}",Sha256::digest(bytes)),"retained_reason":null},
        "ciphertext_base64":STANDARD.encode(bytes)
      })).collect::<Vec<_>>()
    }]})
}

fn write(root: &Path, value: &Value) -> std::path::PathBuf {
    let path = root.join("snapshot.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

#[test]
fn complete_snapshots_converge_without_executables_and_preserve_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path());
    let input = write(root.path(), &snapshot(&[("item/section/a", b"cipher-a")]));
    delivery::import(&cfg, &input, true, &[]).unwrap();
    assert!(!cfg.state_dir.exists());
    delivery::import(&cfg, &input, false, &[]).unwrap();
    // Miss a generation, then receive both old and new fields.
    write(
        root.path(),
        &snapshot(&[
            ("item/section/a", b"cipher-a"),
            ("item/section/b", b"cipher-b"),
        ]),
    );
    delivery::import(&cfg, &input, false, &[]).unwrap();
    let a = cfg.config.password_store_dir.join("item/section/a.gpg");
    fs::write(&a, b"local-change").unwrap();
    assert!(delivery::import(&cfg, &input, false, &[]).is_err());
    assert_eq!(fs::read(&a).unwrap(), b"local-change");
    delivery::import(&cfg, &input, false, &["item/section/a".into()]).unwrap();
    assert_eq!(fs::read(a).unwrap(), b"cipher-a");
    // Remote disappearance never removes local ciphertext.
    write(root.path(), &snapshot(&[]));
    delivery::import(&cfg, &input, false, &[]).unwrap();
    assert!(cfg
        .config
        .password_store_dir
        .join("item/section/b.gpg")
        .exists());
    let exported = root.path().join("export.json");
    delivery::export(&cfg, &exported).unwrap();
    let data: Value = serde_json::from_slice(&fs::read(exported).unwrap()).unwrap();
    assert_eq!(data["items"][0]["fields"].as_array().unwrap().len(), 2);
    assert_eq!(data["last_source_success_at"], "2026-01-01T00:00:00Z");
}

#[test]
fn corruption_duplicates_traversal_and_symlinks_fail_before_writes() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path());
    for value in [
        snapshot(&[("../escape", b"cipher")]),
        snapshot(&[("a/b/c", b"cipher"), ("a/b/c", b"cipher")]),
        {
            let mut v = snapshot(&[("a/b/c", b"cipher")]);
            v["items"][0]["fields"][0]["ciphertext_base64"] = json!("broken");
            v
        },
    ] {
        let input = write(root.path(), &value);
        assert!(delivery::import(&cfg, &input, false, &[]).is_err());
        assert!(!cfg.state_dir.exists());
    }
    std::os::unix::fs::symlink(root.path(), cfg.config.password_store_dir.join("a")).unwrap();
    let input = write(root.path(), &snapshot(&[("a/b/c", b"cipher")]));
    assert!(delivery::import(&cfg, &input, false, &[]).is_err());
    assert!(!root.path().join("b/c.gpg").exists());
}
