# proton-pass-sync

`proton-pass-sync` creates an encrypted, offline GNU pass mirror of selected
Proton Pass data. Proton Pass remains authoritative; the mirror makes already
synchronized values available through `pass` when Proton or the network is
unavailable.

The `0.1` data path is deliberately narrow and one-way:

```text
existing pass-cli session -> active custom items -> GNU pass ciphertext
```

The synchronizer never logs in, accepts a token, writes to Proton Pass, or
silently deletes local entries.

> [!WARNING]
> This project handles secrets. Start with a disposable vault and fake values,
> run `sync --dry-run`, and read [SECURITY.md](SECURITY.md) before using it with
> important data.

## What is mirrored

Version `0.1` reads active **custom items** from one vault. Each nonempty text
or hidden field maps to a natural GNU pass path:

```text
<item title>/<section name>/<field name>
```

For example, the `token` field in the `production` section of an item named
`compiler-service` becomes:

```text
compiler-service/production/token
```

An optional target prefix is prepended to that path. Values are preserved as
UTF-8 and sent directly to GNU pass for GPG encryption. TOTP and timestamp
fields, notes, attachments, and every non-custom item type are ignored.

Path components are validated before anything is written. Empty components,
`.` and `..`, separators, control characters, symlinks, duplicates, and
case-folding collisions are rejected as a complete-sync error.

## Requirements

- Linux or macOS. NixOS and Home Manager are supported through the flake.
- Proton Pass CLI `>= 2.2.2` and `< 3.0.0`.
- GNU pass backed by a working GPG identity.
- A password store without a `.git` directory. Git-backed stores are refused
  in `0.1` because GNU pass can make automatic commits outside the sync
  transaction.

## Provision access separately

Authentication is intentionally outside this tool. Create a dedicated,
expiring Proton Pass personal access token, grant it **viewer** access to only
the source vault, and establish a persistent `pass-cli` session yourself. Do
not put the PAT in this repository, the sync configuration, a Home Manager
option, a timer environment, or a command shown in logs.

Follow Proton's official [personal access token
instructions](https://protonpass.github.io/pass-cli/commands/personal-access-token/)
and [login instructions](https://protonpass.github.io/pass-cli/commands/login/).
Use the [configuration
reference](https://protonpass.github.io/pass-cli/get-started/configuration/) for
session storage and key-provider persistence. Provide the PAT to
`pass-cli login` only for the provisioning command, clear it from the
environment immediately afterward, and verify the stored session:

```console
$ pass-cli info
$ pass-cli vault list --output json
```

The scheduled synchronizer subsequently reuses that session. PAT expiry or
revocation makes synchronization fail closed while the last encrypted local
copy remains available.

## Initialize GNU pass

Create or import the intended GPG key, then initialize a dedicated password
store. The examples below do not create or expose private key material:

```console
$ export PASSWORD_STORE_DIR="$HOME/.password-store"
$ pass init YOUR_GPG_KEY_ID
$ test -f "$PASSWORD_STORE_DIR/.gpg-id"
$ test ! -e "$PASSWORD_STORE_DIR/.git"
```

If the store already exists, back it up and confirm that `pass insert` and
`pass show` work manually before synchronizing.

## Install

Run directly from the flake:

```console
$ nix run github:Napolitain/proton-pass-sync -- doctor
```

Or install the package from the flake output appropriate to your system. A
release build can also be produced with `cargo build --release`; the binary is
`target/release/proton-pass-sync`.

## Configure

Create an owner-readable-only TOML file containing non-secret metadata. The
stable vault share ID can be obtained from `pass-cli vault list --output json`.
Never put a PAT or a field value here.

```toml
schema_version = 1
vault_share_id = "example-share-id"

# Optional values; omitted values use the documented defaults.
# password_store_dir must be absolute when set.
# password_store_dir = "/home/example/.password-store"
target_prefix = ""
stale_after_secs = 86400

# Optional absolute command overrides for scheduled environments.
# proton_cli = "/absolute/path/to/pass-cli"
# pass_command = "/absolute/path/to/pass"
# gpg_command = "/absolute/path/to/gpg"
```

Unknown configuration keys are rejected. The default path is
`$XDG_CONFIG_HOME/proton-pass-sync/config.toml` (normally
`~/.config/proton-pass-sync/config.toml`). Pass a different file to any command
with the global `--config PATH` option.

When omitted, `password_store_dir` is `$HOME/.password-store`. The owner-only
manifest, lock, and recovery journal live below
`$XDG_STATE_HOME/proton-pass-sync`, falling back to
`~/.local/state/proton-pass-sync`.

## Commands

```console
$ proton-pass-sync doctor
$ proton-pass-sync sync --dry-run
$ proton-pass-sync sync
$ proton-pass-sync sync --full
$ proton-pass-sync status
$ proton-pass-sync status --json
$ proton-pass-sync sync --accept-remote compiler-service/production/token
$ proton-pass-sync prune compiler-service/production/token
```

- `doctor` checks compatible executables, the existing Proton session and
  vault access, GNU pass initialization, recipients, and configuration. It does
  not fetch secret fields.
- `sync --dry-run` performs a secret-free inventory comparison without changing
  password entries or the manifest. It reports custom-item deltas plus
  conflicts detectable from the existing manifest and local ciphertext. Field
  and path details for new or changed items remain unresolved until a real sync
  fetches those item details.
- `sync` uses Proton item modification times to fetch only changed custom
  items. `sync --full` refetches all active custom items as a repair path.
- `--accept-remote PATH` is an explicit, one-path decision to overwrite a
  locally changed or unmanaged destination and adopt the Proton value.
- `status` reports cache age, conflicts, and entries retained after they became
  unavailable remotely. JSON output is intended for monitoring.
- `prune PATH` is the only removal operation. It confirms interactively and is
  never run by the Home Manager scheduler.

Only one sync may run at a time. A complete remote inventory and the complete
destination path graph are validated before commit. Secret values are fetched
per changed item, encrypted in a same-filesystem staging store, and moved into
place atomically with a recovery journal.

## Fail-safe behavior

The password store remains unchanged when Proton authentication, networking,
JSON decoding, inventory validation, encryption, or staging fails. The tool
also stops before mutation when:

- a destination exists but is not owned by the sync manifest;
- an owned ciphertext file was changed or deleted locally;
- any destination is a symlink or resolves to an unsafe/colliding path; or
- the password store contains `.git`.

If a remote item or field is trashed, removed, renamed, emptied, or no longer
visible, its last local ciphertext is retained and marked remote-missing.
Network or permission failures are never interpreted as deletion. Inspect the
condition with `status`; remove a retained entry only with an explicit `prune`.

## Home Manager

Add the flake input and import its module. This example intentionally leaves
the service disabled, which is also the default:

```nix
{ inputs, ... }: {
  imports = [ inputs.proton-pass-sync.homeManagerModules.default ];

  services.proton-pass-sync = {
    enable = false;
  };
}
```

Here `inputs.proton-pass-sync.url = "github:Napolitain/proton-pass-sync";` is
declared in the consuming flake and that flake passes `inputs` to its Home
Manager modules.

When enabled explicitly, the module can install/configure the package and GNU
pass/GPG integration. It accepts either structured non-secret `settings` or an
exact `configFile` path, never both. Scheduling defaults to enabled for an
enabled service and creates a Linux user systemd service/timer or a macOS
LaunchAgent that runs at login and hourly; set
`services.proton-pass-sync.schedule.enable = false` to opt out. The module never
provisions a PAT, GPG private key, or authenticated Proton session.

With `configFile` and scheduling enabled, its `password_store_dir` must match
`programs.password-store.settings.PASSWORD_STORE_DIR` (or that option's
default), because the Linux systemd sandbox grants write access to that path.

## Offline acceptance check

Use a disposable custom item with fake text and hidden fields:

1. Run `doctor`, then `sync --dry-run` and `sync` while online.
2. Confirm the expected paths using `pass show`.
3. Disable the network or make Proton unavailable without logging out or
   deleting local state.
4. Confirm `proton-pass-sync sync` fails without changing the store.
5. Confirm the previously mirrored value is still available with `pass show`.

This proves the offline fallback: synchronization needs Proton, but reading the
last successfully encrypted mirror does not.

## Development

```console
$ cargo fmt --check
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test --all-targets --all-features
$ nix flake check
```

All fixtures use obviously fake values. Tests must never depend on a real
Proton session, PAT, password store, or GPG home.

## License

MIT. See [LICENSE](LICENSE).
