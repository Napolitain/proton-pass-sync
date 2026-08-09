# Proton Pass CLI fixtures

These files model the JSON emitted by supported Proton Pass CLI releases. They
were written from the public `pass-cli` Rust serialization types; they were not
captured from a real account.

Every identifier and value is synthetic. Keep it that way: never replace a
fixture with live command output, because item-view JSON contains plaintext
secrets.

- `2.2.2/item-list.json` is the secret-free active custom-item inventory
  requested by the synchronizer.
- `2.2.2/item-view-custom.json` is one custom item containing supported text
  and hidden fields, ignored empty/TOTP/timestamp fields, and multiple
  sections.
- The `2.2.5` fixtures exercise the same supported contract with different
  timestamps and names so compatibility does not accidentally depend on one
  sample.
