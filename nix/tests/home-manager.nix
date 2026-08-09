{
  home-manager,
  module,
  package,
  pkgs,
}:

let
  isLinux = pkgs.stdenv.hostPlatform.isLinux;
  homeDirectory = if pkgs.stdenv.hostPlatform.isDarwin then "/Users/tester" else "/home/tester";

  mkHome =
    extraModule:
    home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        module
        {
          home = {
            username = "tester";
            inherit homeDirectory;
            stateVersion = "26.05";
          };
        }
        extraModule
      ];
    };

  disabled = mkHome { };

  generated = mkHome {
    home.sessionVariables.PROTON_PASS_LINUX_KEYRING = "dbus";

    services.proton-pass-sync = {
      enable = true;
      settings = {
        vaultShareId = "test-vault-share";
        targetPrefix = "coding";
      };
    };
  };

  externalConfigPath = "/run/user/1000/proton-pass-sync.toml";
  external = mkHome {
    services.proton-pass-sync = {
      enable = true;
      configFile = externalConfigPath;
    };
  };

  generatedConfig = generated.config.xdg.configFile."proton-pass-sync/config.toml".source;

  disabledIsInert =
    !disabled.config.programs.gpg.enable
    && !disabled.config.programs.password-store.enable
    && !(builtins.elem package disabled.config.home.packages)
    && !(builtins.hasAttr "protonPassSyncState" disabled.config.home.activation)
    && !(builtins.hasAttr "proton-pass-sync" disabled.config.systemd.user.services)
    && !(builtins.hasAttr "proton-pass-sync" disabled.config.launchd.agents);

  generatedProgramsAreEnabled =
    generated.config.programs.gpg.enable && generated.config.programs.password-store.enable;

  generatedPackageIsInstalled = builtins.elem package generated.config.home.packages;

  generatedFileExists = builtins.hasAttr "proton-pass-sync/config.toml" generated.config.xdg.configFile;

  generatedScheduleExists =
    if isLinux then
      builtins.hasAttr "proton-pass-sync" generated.config.systemd.user.services
      && builtins.hasAttr "proton-pass-sync" generated.config.systemd.user.timers
    else
      generated.config.launchd.agents.proton-pass-sync.enable;

  generatedSessionDir =
    if isLinux then
      "${homeDirectory}/.local/share/proton-pass-cli/.session"
    else
      "${homeDirectory}/Library/Application Support/proton-pass-cli/.session";

  generatedEnvironmentIsSafe =
    if isLinux then
      let
        service = generated.config.systemd.user.services.proton-pass-sync.Service;
      in
      builtins.elem "PROTON_PASS_LINUX_KEYRING=dbus" service.Environment
      && builtins.elem "PROTON_PASS_SESSION_DIR=${generatedSessionDir}" service.Environment
      && builtins.elem generatedSessionDir service.ReadWritePaths
      && builtins.elem generated.config.programs.gpg.homedir service.ReadWritePaths
    else
      let
        environment = generated.config.launchd.agents.proton-pass-sync.config.EnvironmentVariables;
      in
      !(environment ? PROTON_PASS_LINUX_KEYRING)
      && environment.PROTON_PASS_SESSION_DIR == generatedSessionDir;

  externalPathIsExact =
    if isLinux then
      lib.hasInfix externalConfigPath (
        builtins.head external.config.systemd.user.services.proton-pass-sync.Service.ExecStart
      )
    else
      builtins.elem externalConfigPath external.config.launchd.agents.proton-pass-sync.config.ProgramArguments;

  lib = pkgs.lib;
in
assert disabledIsInert;
assert lib.assertMsg generatedProgramsAreEnabled
  "generated mode did not enable gpg and password-store";
assert lib.assertMsg generatedPackageIsInstalled "generated mode did not install proton-pass-sync";
assert lib.assertMsg generatedFileExists "generated mode did not create its TOML file";
assert lib.assertMsg generatedScheduleExists "generated mode did not create its platform scheduler";
assert lib.assertMsg generatedEnvironmentIsSafe
  "generated mode did not propagate the keyring or isolate writable session state";
assert externalPathIsExact;
pkgs.runCommand "proton-pass-sync-home-manager-test" { } ''
  grep -F 'schema_version = 1' ${generatedConfig} >/dev/null
  grep -F 'vault_share_id = "test-vault-share"' ${generatedConfig} >/dev/null
  grep -F 'target_prefix = "coding"' ${generatedConfig} >/dev/null
  grep -F 'stale_after_secs = 86400' ${generatedConfig} >/dev/null
  touch "$out"
''
