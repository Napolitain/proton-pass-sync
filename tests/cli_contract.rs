use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proton-pass-sync"))
}

#[test]
fn help_exposes_only_the_v1_command_surface() {
    binary()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("sync"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("prune"))
        .stdout(predicate::str::contains("--config"))
        .stdout(predicate::str::contains("login").not())
        .stdout(predicate::str::contains("token").not());
}

#[test]
fn configuration_rejects_a_token_setting_without_echoing_its_value() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let config = directory.path().join("config.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 1
vault_share_id = "fixture-share"
password_store_dir = "{}"
proton_personal_access_token = "fixture-credential-value"
"#,
            directory.path().join("store").display()
        ),
    )
    .expect("write configuration");

    binary()
        .args(["--config", config.to_str().expect("UTF-8 path"), "doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid configuration"))
        .stderr(predicate::str::contains("details withheld"))
        .stderr(predicate::str::contains("fixture-credential-value").not());
}

#[test]
fn configuration_rejects_a_future_schema_before_running_children() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let config = directory.path().join("config.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 999
vault_share_id = "fixture-share"
password_store_dir = "{}"
"#,
            directory.path().join("store").display()
        ),
    )
    .expect("write configuration");

    binary()
        .args(["--config", config.to_str().expect("UTF-8 path"), "doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported configuration schema_version 999",
        ));
}
