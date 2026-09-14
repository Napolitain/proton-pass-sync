{ pkgs }:
pkgs.writeShellApplication {
  name = "proton-pass-system-provision";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.gnupg
    pkgs.systemd
    pkgs.jq
  ];
  text = ''
    if [[ "$#" != 3 ]]; then
      echo 'Usage (as root): proton-pass-system-provision PUBLIC_KEY_FILE FINGERPRINT VAULT_SHARE_ID' >&2
      echo 'The token is read with echo disabled from the controlling terminal.' >&2
      exit 64
    fi
    [[ $(id -u) == 0 ]] || { echo 'Run this provisioning command as root.' >&2; exit 1; }
    key_file=$1 fingerprint=$2 vault=$3
    [[ "$fingerprint" =~ ^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$ ]] || exit 64
    # JSON quoted strings are valid TOML basic strings for this restricted ID.
    [[ "$vault" =~ ^[A-Za-z0-9_=-]+$ ]] || { echo 'Invalid vault share ID' >&2; exit 64; }
    for directory in /etc/proton-pass-sync /etc/credstore.encrypted; do
      [[ ! -L "$directory" ]] || exit 1
      if [[ -e "$directory" ]]; then
        [[ $(stat -c %u "$directory") == 0 ]] || exit 1
      fi
      install -d -m0700 -o root -g root "$directory"
    done
    for existing in /etc/credstore.encrypted/proton-token /etc/proton-pass-sync/recipient.asc /etc/proton-pass-sync/recipient.fingerprint /etc/proton-pass-sync/vault.toml; do
      [[ ! -e "$existing" && ! -L "$existing" ]] || {
        echo 'Existing provisioning found; refusing implicit token or recipient rotation.' >&2
        exit 1
      }
    done
    umask 077
    temporary=$(mktemp -d /etc/proton-pass-sync/.provision-XXXXXXXX)
    trap 'unset token; rm -rf "$temporary"' EXIT
    export GNUPGHOME="$temporary/gnupg"
    mkdir -m0700 "$GNUPGHOME"
    gpg --batch --import -- "$key_file" >/dev/null 2>&1
    gpg --batch --export "$fingerprint" > "$temporary/recipient.asc"
    [[ -s "$temporary/recipient.asc" ]] || exit 1
    printf '%s\n' "$fingerprint" > "$temporary/recipient.fingerprint"
    printf 'schema_version = 1\nvault_share_id = %s\ntarget_prefix = ""\n' "$(printf '%s' "$vault" | jq -Rs .)" > "$temporary/vault.toml"
    read -r -s -p 'Proton viewer token: ' token < /dev/tty
    printf '\n' > /dev/tty
    [[ -n "$token" ]] || exit 1
    printf '%s' "$token" | systemd-creds encrypt --with-key=auto --name=proton-token - "$temporary/proton-token"
    unset token
    systemd-creds decrypt --name=proton-token "$temporary/proton-token" /dev/null
    install -m0600 "$temporary/recipient.asc" /etc/proton-pass-sync/recipient.asc
    install -m0600 "$temporary/recipient.fingerprint" /etc/proton-pass-sync/recipient.fingerprint
    # Root-only parent; PID 1 binds this non-secret file into delivery.
    install -m0644 "$temporary/vault.toml" /etc/proton-pass-sync/vault.toml
    install -m0600 "$temporary/proton-token" /etc/credstore.encrypted/proton-token
    echo 'Provisioned. No service was started. Recipient private keys remain with the desktop user.'
  '';
}
