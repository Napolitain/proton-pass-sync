#![cfg(unix)]

use proton_pass_sync::config::Config;
use proton_pass_sync::store::StagingArea;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn executable(name: &str) -> Option<PathBuf> {
    let found = env::var_os("PATH")
        .into_iter()
        .flat_map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file());
    assert!(
        found.is_some() || env::var_os("CI").is_none(),
        "{name} is required by the CI integration-test environment"
    );
    found
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn run_gpg(gpg: &Path, home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(gpg)
        .env("GNUPGHOME", home)
        .args(arguments)
        .output()
        .expect("run isolated GPG")
}

#[test]
fn stages_ciphertext_that_remains_decryptable_offline() {
    let (Some(pass), Some(gpg)) = (executable("pass"), executable("gpg")) else {
        eprintln!("skipping real GNU pass/GPG test because the tools are unavailable");
        return;
    };

    let directory = tempfile::tempdir().expect("create isolated integration directory");
    let gpg_home = directory.path().join("gnupg");
    fs::create_dir(&gpg_home).expect("create isolated GPG home");
    fs::set_permissions(&gpg_home, fs::Permissions::from_mode(0o700))
        .expect("secure isolated GPG home");

    let generated = run_gpg(
        &gpg,
        &gpg_home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "proton-pass-sync fixture <fixture@invalid.example>",
            "rsa2048",
            "encr",
            "0",
        ],
    );
    assert!(
        generated.status.success(),
        "fixture key generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let listed = run_gpg(
        &gpg,
        &gpg_home,
        &["--batch", "--with-colons", "--list-secret-keys"],
    );
    assert!(listed.status.success(), "cannot list fixture key");
    let listing = String::from_utf8(listed.stdout).expect("GPG listing is UTF-8");
    let fingerprint = listing
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.first() == Some(&"fpr") {
                fields.get(9).map(|value| (*value).to_owned())
            } else {
                None
            }
        })
        .expect("fixture key has a fingerprint");

    let store = directory.path().join("password-store");
    fs::create_dir(&store).expect("create isolated password store");
    fs::write(store.join(".gpg-id"), format!("{fingerprint}\n"))
        .expect("initialize isolated password store");

    let pass_wrapper = directory.path().join("pass-with-isolated-gpg");
    fs::write(
        &pass_wrapper,
        format!(
            "#!/bin/sh\nexport GNUPGHOME={}\nexec {} \"$@\"\n",
            shell_quote(&gpg_home),
            shell_quote(&pass),
        ),
    )
    .expect("write GNU pass wrapper");
    fs::set_permissions(&pass_wrapper, fs::Permissions::from_mode(0o700))
        .expect("make GNU pass wrapper executable");

    let config = Config {
        vault_share_id: "fixture-share".into(),
        password_store_dir: store,
        target_prefix: String::new(),
        proton_cli: PathBuf::from("pass-cli"),
        pass_command: pass_wrapper,
        gpg_command: gpg.clone(),
        stale_after_secs: 86_400,
    };
    let plaintext = b"fixture-offline-value\nfixture-second-line";
    let staging = StagingArea::new(&config).expect("create encrypted staging store");
    let staged = staging
        .stage("project/production/token", plaintext)
        .expect("encrypt fixture value through GNU pass");

    let ciphertext = fs::read(&staged.source).expect("read staged ciphertext");
    assert_ne!(
        ciphertext.as_slice(),
        plaintext,
        "the staged file must be ciphertext"
    );
    let stage_root = staged
        .source
        .ancestors()
        .nth(3)
        .expect("staged path has the natural three-component suffix");
    let decrypted = Command::new(&config.pass_command)
        .env("PASSWORD_STORE_DIR", stage_root)
        .args(["show", "project/production/token"])
        .output()
        .expect("read staged fixture value through GNU pass");
    assert!(
        decrypted.status.success(),
        "fixture ciphertext did not decrypt: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(decrypted.stdout, plaintext);
}
