{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.proton-pass-sync-system;
  state = "/var/lib/proton-pass-sync";
  runtime = "/run/proton-pass-sync";
  target = config.users.users.${cfg.recipient};
  sync = "${cfg.package}/bin/proton-pass-sync";
  cli = "${cfg.protonCliPackage}/bin/pass-cli";
  toml = pkgs.formats.toml { };
  # Private vault metadata is provisioned separately; only fixed command paths
  # and paths owned by the system are appended here.
  producer = pkgs.writeShellScript "proton-pass-produce" ''
    set -euo pipefail
    umask 077
    export HOME=${runtime} GNUPGHOME=${runtime}/gnupg
    export PROTON_PASS_SESSION_DIR=${runtime}/proton PROTON_PASS_KEY_PROVIDER=fs
    export PROTON_PASS_NO_UPDATE_CHECK=1 PROTON_PASS_DISABLE_TELEMETRY=1
    export PASS_LOG_LEVEL=off MUON_LOG_LEVEL=off PASSWORD_STORE_ENABLE_EXTENSIONS=false
    export PASSWORD_STORE_GPG_OPTS="--no-auto-key-retrieve --auto-key-locate clear"
    mkdir -p "$GNUPGHOME" ${state}/store
    trap 'rm -rf ${runtime}/proton ${runtime}/gnupg' EXIT
    ${pkgs.gnupg}/bin/gpg --batch --import "$CREDENTIALS_DIRECTORY/recipient-key" >/dev/null 2>&1
    fingerprint=$(cat "$CREDENTIALS_DIRECTORY/recipient-fingerprint")
    [[ "$fingerprint" =~ ^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$ ]] || exit 1
    ${pkgs.gnupg}/bin/gpg --batch --with-colons --fingerprint "$fingerprint" > ${runtime}/keys
    ${pkgs.gawk}/bin/awk -F: -v expected="$fingerprint" '$1 == "fpr" && toupper($10) == toupper(expected) { found=1 } END { exit !found }' ${runtime}/keys
    # Recipient rotation must be explicit: don't mix recipients silently.
    if test -e ${state}/store/.gpg-id; then
      test "$(cat ${state}/store/.gpg-id)" = "$fingerprint"
    else
      printf '%s\n' "$fingerprint" > ${state}/store/.gpg-id
    fi
    printf '%s:6:\n' "$fingerprint" | ${pkgs.gnupg}/bin/gpg --batch --import-ownertrust >/dev/null 2>&1
    cat "$CREDENTIALS_DIRECTORY/vault-config" > ${runtime}/config.toml
    printf '\n' >> ${runtime}/config.toml
    cat ${
      toml.generate "producer-paths.toml" {
        password_store_dir = "${state}/store";
        proton_cli = cli;
        pass_command = "${pkgs.pass}/bin/pass";
        gpg_command = "${pkgs.gnupg}/bin/gpg";
      }
    } >> ${runtime}/config.toml
    # Only the login child inherits the token; stdout/stderr may contain secrets.
    if ! PROTON_PASS_PERSONAL_ACCESS_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/proton-token")" \
      ${cli} login </dev/null >/dev/null 2>&1; then
      echo 'Proton authentication failed' >&2
      exit 1
    fi
    ${sync} --config ${runtime}/config.toml --state-dir ${state}/sync sync
    ${sync} --config ${runtime}/config.toml --state-dir ${state}/sync export-ciphertext --output ${state}/export/snapshot.json
  '';
  deliver = pkgs.writeShellScript "proton-pass-deliver" ''
    set -euo pipefail
    umask 077
    cat /run/proton-pass-delivery/source.toml > /run/proton-pass-delivery/config.toml
    printf '\n' >> /run/proton-pass-delivery/config.toml
    cat ${
      toml.generate "delivery-paths.toml" {
        password_store_dir = cfg.passwordStore;
      }
    } >> /run/proton-pass-delivery/config.toml
    exec ${sync} --config /run/proton-pass-delivery/config.toml \
      --state-dir /var/lib/proton-pass-delivery \
      import-ciphertext --input /run/proton-pass-delivery/snapshot.json
  '';
  scheduler = pkgs.writeShellApplication {
    name = "proton-pass-schedule";
    runtimeInputs = [
      pkgs.systemd
      pkgs.coreutils
      pkgs.gawk
    ];
    text = ''
      recipient=${lib.escapeShellArg cfg.recipient}
      sessions() {
        loginctl list-sessions --no-legend --no-pager | awk '{print $1}' | while read -r session; do
          name=$(loginctl show-session "$session" -p Name --value) || continue
          class=$(loginctl show-session "$session" -p Class --value) || continue
          state=$(loginctl show-session "$session" -p State --value) || continue
          if [[ "$name" == "$recipient" && "$class" =~ ^user(-early|-light)?$ && "$state" =~ ^(active|online)$ ]]; then
            printf '%s\n' "$session"
          fi
        done | sort
      }
      current=$(sessions)
      if [[ -z "$current" ]]; then
        rm -f /var/lib/proton-pass-schedule/sessions
        exit 0
      fi
      now=$(date +%s)
      last=0
      previous=""
      if [[ -f /var/lib/proton-pass-schedule/attempt ]]; then read -r last < /var/lib/proton-pass-schedule/attempt; fi
      if [[ -f /var/lib/proton-pass-schedule/sessions ]]; then previous=$(cat /var/lib/proton-pass-schedule/sessions); fi
      # New login permits an immediate attempt; otherwise failures retry hourly.
      if [[ "$current" == "$previous" ]] && (( now >= last && now - last < 3600 )); then exit 0; fi
      [[ -n "$(sessions)" ]] || exit 0
      printf '%s\n' "$now" > /var/lib/proton-pass-schedule/attempt.new
      mv /var/lib/proton-pass-schedule/attempt.new /var/lib/proton-pass-schedule/attempt
      printf '%s\n' "$current" > /var/lib/proton-pass-schedule/sessions.new
      mv /var/lib/proton-pass-schedule/sessions.new /var/lib/proton-pass-schedule/sessions
      systemctl start proton-pass-producer.service
      systemctl start proton-pass-delivery.service
    '';
  };
  hardened = {
    Type = "oneshot";
    UMask = "0077";
    NoNewPrivileges = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectSystem = "strict";
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    RestrictSUIDSGID = true;
    RestrictRealtime = true;
    CapabilityBoundingSet = "";
    LimitCORE = 0;
    TimeoutStartSec = "10min";
  };
in
{
  options.services.proton-pass-sync-system = {
    enable = lib.mkEnableOption "isolated Proton Pass to desktop ciphertext delivery";
    recipient = lib.mkOption {
      type = lib.types.str;
      description = "Explicit local human recipient.";
    };
    passwordStore = lib.mkOption {
      type = lib.types.str;
      default = "${target.home}/.password-store";
    };
    credentialDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/etc/proton-pass-sync";
    };
    tokenFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/credstore.encrypted/proton-token";
    };
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    };
    protonCliPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./proton-cli.nix { };
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = target.isNormalUser;
        message = "proton-pass-sync recipient must be an explicit normal user";
      }
      {
        assertion = builtins.all (entry: !(builtins.elem entry config.nix.settings.trusted-users)) (
          [
            cfg.recipient
            "*"
            "@${target.group}"
          ]
          ++ map (group: "@${group}") target.extraGroups
        );
        message = "Proton credential isolation requires an untrusted Nix recipient";
      }
      {
        assertion =
          lib.hasPrefix "/" cfg.passwordStore
          && lib.hasPrefix "/" cfg.tokenFile
          && lib.hasPrefix "/" cfg.credentialDirectory;
        message = "Proton service paths must be absolute";
      }
    ];
    systemd = {
      services = {
        proton-pass-producer = {
          description = "Fetch Proton custom fields under an isolated service UID";
          path = [ pkgs.coreutils ];
          serviceConfig = hardened // {
            DynamicUser = true;
            ProtectHome = true;
            StateDirectory = "proton-pass-sync";
            StateDirectoryMode = "0700";
            RuntimeDirectory = "proton-pass-sync";
            RuntimeDirectoryMode = "0700";
            LoadCredentialEncrypted = [ "proton-token:${cfg.tokenFile}" ];
            LoadCredential = [
              "recipient-key:${cfg.credentialDirectory}/recipient.asc"
              "recipient-fingerprint:${cfg.credentialDirectory}/recipient.fingerprint"
              "vault-config:${cfg.credentialDirectory}/vault.toml"
            ];
            ExecStart = producer;
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
          };
        };
        proton-pass-delivery = {
          description = "Install ciphertext into the recipient's GNU pass store";
          path = [ pkgs.coreutils ];
          serviceConfig = hardened // {
            User = cfg.recipient;
            ProtectHome = "read-only";
            PrivateNetwork = true;
            RestrictAddressFamilies = [ "AF_UNIX" ];
            RuntimeDirectory = "proton-pass-delivery";
            RuntimeDirectoryMode = "0700";
            StateDirectory = "proton-pass-delivery";
            StateDirectoryMode = "0700";
            BindReadOnlyPaths = [
              "/var/lib/private/proton-pass-sync/export/snapshot.json:/run/proton-pass-delivery/snapshot.json"
              "${cfg.credentialDirectory}/vault.toml:/run/proton-pass-delivery/source.toml"
            ];
            ReadWritePaths = [ cfg.passwordStore ];
            ExecStart = deliver;
          };
        };
        proton-pass-schedule = {
          description = "Schedule fixed Proton sync jobs only during human login sessions";
          serviceConfig = hardened // {
            ExecStart = lib.getExe scheduler;
            ProtectHome = true;
            PrivateNetwork = true;
            StateDirectory = "proton-pass-schedule";
            StateDirectoryMode = "0700";
            RestrictAddressFamilies = [ "AF_UNIX" ];
            TimeoutStartSec = "25min";
          };
        };
      };
      timers.proton-pass-schedule = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "1min";
          OnUnitInactiveSec = "1min";
        };
      };
    };
  };
}
