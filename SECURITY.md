# Security policy

`proton-pass-sync` handles plaintext secrets briefly while copying them from an
authenticated Proton Pass CLI session into GPG-encrypted GNU pass entries. A
bug can therefore have a larger impact than it would in an ordinary CLI.

## Supported versions

Until the first stable release, only the latest tagged `0.1.x` release is
supported. Security fixes are not promised for older tags or arbitrary
development commits.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include
real tokens, vault identifiers, item names, password-store paths, logs that may
contain secrets, private keys, or encrypted password-store contents in a
report.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Advisories** and **Report a vulnerability**.
3. Describe the affected version, operating system, and minimal reproduction
   using disposable fake data.

You should receive an acknowledgement within seven days. We will validate the
report, agree on disclosure timing, and publish a security advisory and fixed
release when appropriate. If private vulnerability reporting is unavailable,
open a public issue containing only a request for a private contact channel.

## Security boundaries

- The tool reuses an existing `pass-cli` session. It does not create, accept,
  persist, renew, or print a Proton personal access token.
- Proton Pass is authoritative. The GNU pass store is an encrypted offline
  mirror, not a second source of truth.
- Only active custom-item text and hidden fields are in scope for `0.1.x`.
- The tool intentionally refuses Git-backed GNU pass stores. Automatic Git
  commits are outside its transaction boundary and can leak metadata.
- Unexpected remote removals, local modifications, and unmanaged destination
  paths are fail-safe conditions. Remote absence never silently deletes local
  ciphertext.
- Secret values must not appear in diagnostics, scheduled-service logs,
  manifests, journals, command arguments, or temporary plaintext files.

## Safer operation

Use a dedicated, expiring Proton Pass personal access token with viewer access
to only the vault being mirrored. Protect the local account, GPG private key,
Proton session directory, GNU pass store, and sync state directory with the
same care as the source vault. Review `proton-pass-sync sync --dry-run` before
the first write and use disposable credentials when testing.
