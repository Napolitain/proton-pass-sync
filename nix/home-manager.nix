{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.proton-pass-sync;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  system = pkgs.stdenv.hostPlatform.system;
  isLinux = pkgs.stdenv.hostPlatform.isLinux;
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

  configRelativePath = "proton-pass-sync/config.toml";
  generatedConfigPath = "${config.xdg.configHome}/${configRelativePath}";
  stateDirectory = "${config.xdg.stateHome}/proton-pass-sync";
  defaultPasswordStoreDir = "${config.home.homeDirectory}/.password-store";
  defaultProtonSessionDir =
    if isDarwin then
      "${config.home.homeDirectory}/Library/Application Support/proton-pass-cli/.session"
    else
      "${config.xdg.dataHome}/proton-pass-cli/.session";
  protonSessionDir = toString (
    config.home.sessionVariables.PROTON_PASS_SESSION_DIR or defaultProtonSessionDir
  );
  protonEnvironment = {
    XDG_STATE_HOME = config.xdg.stateHome;
    PROTON_PASS_SESSION_DIR = protonSessionDir;
    PROTON_PASS_NO_UPDATE_CHECK = "1";
  }
  // lib.optionalAttrs (isLinux && (config.home.sessionVariables ? PROTON_PASS_LINUX_KEYRING)) {
    PROTON_PASS_LINUX_KEYRING = toString config.home.sessionVariables.PROTON_PASS_LINUX_KEYRING;
  };

  settingsType = types.submodule {
    options = {
      vaultShareId = mkOption {
        type = types.str;
        description = "Stable Proton Pass vault share ID to mirror. This is metadata, not a token.";
      };

      passwordStoreDir = mkOption {
        type = types.str;
        default = defaultPasswordStoreDir;
        defaultText = lib.literalExpression ''"''${config.home.homeDirectory}/.password-store"'';
        description = "Absolute path to the GNU pass store.";
      };

      targetPrefix = mkOption {
        type = types.str;
        default = "";
        description = "Optional path prefix below the GNU pass store.";
      };

      protonCli = mkOption {
        type = types.str;
        default = "${config.home.homeDirectory}/.local/bin/pass-cli";
        defaultText = lib.literalExpression ''"''${config.home.homeDirectory}/.local/bin/pass-cli"'';
        description = ''
          Absolute path to a supported pass-cli executable. The upstream user-local
          installation is the default because the nixpkgs package may lag the CLI
          versions supported by proton-pass-sync.
        '';
      };

      passCommand = mkOption {
        type = types.str;
        default = "${config.programs.password-store.package}/bin/pass";
        defaultText = lib.literalExpression ''"''${config.programs.password-store.package}/bin/pass"'';
        description = "Absolute path to the GNU pass executable.";
      };

      gpgCommand = mkOption {
        type = types.str;
        default = "${config.programs.gpg.package}/bin/gpg";
        defaultText = lib.literalExpression ''"''${config.programs.gpg.package}/bin/gpg"'';
        description = "Absolute path to the GnuPG executable.";
      };
    };
  };

  renderedSettings =
    if cfg.settings == null then
      { }
    else
      {
        schema_version = 1;
        vault_share_id = cfg.settings.vaultShareId;
        password_store_dir = cfg.settings.passwordStoreDir;
        target_prefix = cfg.settings.targetPrefix;
        proton_cli = cfg.settings.protonCli;
        pass_command = cfg.settings.passCommand;
        gpg_command = cfg.settings.gpgCommand;
        stale_after_secs = cfg.schedule.staleAfter;
      };

  tomlFormat = pkgs.formats.toml { };
  generatedConfig = tomlFormat.generate "proton-pass-sync.toml" renderedSettings;

  effectiveConfigPath = if cfg.configFile != null then cfg.configFile else generatedConfigPath;

  configuredPasswordStoreDir =
    if cfg.settings != null then
      cfg.settings.passwordStoreDir
    else
      config.programs.password-store.settings.PASSWORD_STORE_DIR or defaultPasswordStoreDir;

  syncArguments = [
    "${cfg.package}/bin/proton-pass-sync"
    "--config"
    effectiveConfigPath
    "sync"
  ];

  settingsPathsAreAbsolute =
    cfg.settings == null
    || builtins.all (value: lib.hasPrefix "/" value) [
      cfg.settings.passwordStoreDir
      cfg.settings.protonCli
      cfg.settings.passCommand
      cfg.settings.gpgCommand
    ];
in
{
  options.services.proton-pass-sync = {
    enable = mkEnableOption "one-way Proton Pass to GNU pass synchronization";

    package = mkOption {
      type = types.package;
      default = self.packages.${system}.default;
      defaultText = lib.literalExpression "inputs.proton-pass-sync.packages.\${pkgs.system}.default";
      description = "The proton-pass-sync package to use.";
    };

    settings = mkOption {
      type = types.nullOr settingsType;
      default = null;
      example = {
        vaultShareId = "share-id-from-pass-cli";
        targetPrefix = "coding";
      };
      description = ''
        Non-secret settings used to generate the proton-pass-sync TOML file.
        Set either this option or configFile when the service is enabled.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/user/1000/proton-pass-sync.toml";
      description = ''
        Absolute path passed unchanged to proton-pass-sync instead of generating
        a configuration file. The file must contain metadata only; authentication
        remains owned by the existing pass-cli session. When scheduling is enabled,
        its password_store_dir must match programs.password-store.settings.PASSWORD_STORE_DIR,
        or the default ~/.password-store, so the Linux service can grant the precise
        writable path without reading TOML during evaluation.
      '';
    };

    schedule = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to install a user timer or LaunchAgent for synchronization.";
      };

      hourly = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to synchronize once per hour.";
      };

      runAtLogin = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to synchronize shortly after login.";
      };

      staleAfter = mkOption {
        type = types.ints.positive;
        default = 86400;
        description = ''
          Age in seconds after which status considers the offline cache stale.
          This value is written only to generated settings; an external configFile
          owns its stale_after_secs value.
        '';
      };
    };
  };

  config = mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = (cfg.settings != null) != (cfg.configFile != null);
            message = "services.proton-pass-sync requires exactly one of settings or configFile";
          }
          {
            assertion = cfg.configFile == null || lib.hasPrefix "/" cfg.configFile;
            message = "services.proton-pass-sync.configFile must be an absolute path";
          }
          {
            assertion = cfg.settings == null || cfg.settings.vaultShareId != "";
            message = "services.proton-pass-sync.settings.vaultShareId must not be empty";
          }
          {
            assertion = settingsPathsAreAbsolute;
            message = "services.proton-pass-sync generated command and password-store paths must be absolute";
          }
          {
            assertion = lib.hasPrefix "/" protonSessionDir;
            message = "the Proton Pass CLI session directory must be an absolute path";
          }
          {
            assertion = !cfg.schedule.enable || cfg.schedule.hourly || cfg.schedule.runAtLogin;
            message = "services.proton-pass-sync.schedule must enable hourly or runAtLogin when scheduling is enabled";
          }
        ];

        home.packages = [ cfg.package ];

        home.activation.protonPassSyncState = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
          run ${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg stateDirectory}
          run ${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg protonSessionDir}
        '';

        programs.gpg.enable = true;
        programs.password-store.enable = true;
      }

      (mkIf (cfg.settings != null) {
        xdg.configFile.${configRelativePath}.source = generatedConfig;
      })

      (mkIf (cfg.schedule.enable && isLinux) {
        systemd.user.services.proton-pass-sync = {
          Unit = {
            Description = "Mirror Proton Pass custom fields into GNU pass";
            After = [ "network-online.target" ];
            Wants = [ "network-online.target" ];
          };

          Service = {
            Type = "oneshot";
            ExecStart = lib.escapeShellArgs syncArguments;
            Environment = lib.mapAttrsToList (name: value: "${name}=${value}") protonEnvironment;
            UMask = "0077";
            NoNewPrivileges = true;
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectClock = true;
            ProtectControlGroups = true;
            ProtectHome = "read-only";
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectSystem = "strict";
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
            RestrictRealtime = true;
            ReadWritePaths = [
              stateDirectory
              configuredPasswordStoreDir
              config.programs.gpg.homedir
              protonSessionDir
            ];
          };
        };

        systemd.user.timers.proton-pass-sync = {
          Unit.Description = "Periodic Proton Pass to GNU pass synchronization";
          Timer = {
            Unit = "proton-pass-sync.service";
            RandomizedDelaySec = "5m";
          }
          // lib.optionalAttrs cfg.schedule.hourly {
            OnCalendar = "hourly";
            Persistent = true;
          }
          // lib.optionalAttrs cfg.schedule.runAtLogin {
            OnStartupSec = "1m";
          };
          Install.WantedBy = [ "timers.target" ];
        };
      })

      (mkIf (cfg.schedule.enable && isDarwin) {
        launchd.agents.proton-pass-sync = {
          enable = true;
          config = {
            ProgramArguments = syncArguments;
            EnvironmentVariables = protonEnvironment;
            ProcessType = "Background";
            Umask = 63;
          }
          // lib.optionalAttrs cfg.schedule.hourly {
            StartInterval = 3600;
          }
          // lib.optionalAttrs cfg.schedule.runAtLogin {
            RunAtLoad = true;
          };
        };
      })
    ]
  );
}
