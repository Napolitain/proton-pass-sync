{
  pkgs,
  module,
  package,
}:
let
  fixtures = ../../tests/fixtures/2.2.2;
  fakeCli = pkgs.writeShellScriptBin "pass-cli" ''
    set -eu
    case "$1" in
      --version) echo 'Proton Pass CLI 2.3.3 (fixture)' ;;
      login)
        test "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" = fixture-master-token
        mkdir -p "$PROTON_PASS_SESSION_DIR"
        printf 'fixture-private-session' > "$PROTON_PASS_SESSION_DIR/session"
        # Give the VM time to probe the live UID and credential boundary.
        sleep 8
        ;;
      info) test -z "''${PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}"; echo '{}' ;;
      item)
        test -z "''${PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}"
        case "$2" in
          list) cat ${fixtures}/item-list.json ;;
          view) cat ${fixtures}/item-view-custom.json ;;
        esac
        ;;
    esac
  '';
in
pkgs.testers.runNixOSTest {
  name = "proton-pass-system-isolation";
  nodes.machine = { ... }: {
    imports = [ module ];
    users.users.alice = {
      isNormalUser = true;
      password = "test-password";
      extraGroups = [ "wheel" ];
    };
    nix.settings.trusted-users = [ "root" ];
    services.getty.autologinUser = "alice";
    services.proton-pass-sync-system = {
      enable = true;
      recipient = "alice";
      inherit package;
      protonCliPackage = fakeCli;
    };
    environment.systemPackages = [
      pkgs.gnupg
      pkgs.pass
      package
      pkgs.jq
    ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl stop proton-pass-schedule.timer")
    machine.succeed("install -d -m700 /etc/proton-pass-sync /etc/credstore.encrypted")
    machine.succeed("su - alice -c 'mkdir -m700 -p ~/.gnupg ~/.password-store'")
    machine.succeed("su - alice -c \"gpg --batch --pinentry-mode loopback --passphrase-file /dev/null --quick-generate-key 'Fixture <fake@invalid.example>' rsa2048 encr 0\"")
    fingerprint = machine.succeed("su - alice -c 'gpg --with-colons --list-secret-keys' | awk -F: '$1==\"fpr\" {print $10; exit}'").strip()
    machine.succeed(f"su - alice -c 'gpg --armor --export {fingerprint}' > /etc/proton-pass-sync/recipient.asc")
    machine.succeed(f"printf '%s\\n' {fingerprint} > /etc/proton-pass-sync/recipient.fingerprint")
    machine.succeed(f"su - alice -c 'pass init {fingerprint}'")
    machine.succeed("printf 'schema_version = 1\\nvault_share_id = \"fixture-share\"\\ntarget_prefix = \"\"\\n' > /etc/proton-pass-sync/vault.toml")
    machine.succeed("chmod 644 /etc/proton-pass-sync/vault.toml")
    machine.succeed("printf fixture-master-token | systemd-creds encrypt --with-key=host --name=proton-token - /etc/credstore.encrypted/proton-token")
    machine.succeed("chmod 600 /etc/credstore.encrypted/proton-token")
    machine.fail("su - alice -c 'cat /etc/credstore.encrypted/proton-token'")
    machine.fail("su - alice -c 'sudo -n true'")
    machine.succeed("su - alice -c 'printf test-password | sudo -S true'")
    machine.succeed("su - alice -c 'sudo -k'")
    machine.succeed("systemctl start --no-block proton-pass-producer.service")
    machine.wait_until_succeeds("test -f /run/proton-pass-sync/proton/session")
    uid = machine.succeed("systemctl show proton-pass-producer -p UID --value").strip()
    assert uid not in ("0", "1000", "")
    pid = machine.succeed("systemctl show proton-pass-producer -p MainPID --value").strip()
    machine.fail(f"su - alice -c 'cat /proc/{pid}/environ'")
    assert "sec:" not in machine.succeed("gpg --homedir /run/proton-pass-sync/gnupg --with-colons --list-secret-keys")
    machine.fail("su - alice -c 'cat /run/credentials/proton-pass-producer.service/proton-token'")
    machine.fail("su - alice -c 'cat /run/proton-pass-sync/proton/session'")
    machine.wait_until_succeeds("test -f /var/lib/private/proton-pass-sync/export/snapshot.json")
    machine.wait_until_succeeds("test ! -d /run/proton-pass-sync")
    machine.fail("su - alice -c 'cat /var/lib/private/proton-pass-sync/export/snapshot.json'")
    machine.succeed("systemctl start proton-pass-delivery.service")
    assert machine.succeed("su - alice -c 'pass show compiler-service/production/token'").strip() == "fixture-hidden-value-alpha"
    snapshot = machine.succeed("cat /var/lib/private/proton-pass-sync/export/snapshot.json")
    assert "fixture-master-token" not in snapshot and "fixture-hidden-value-alpha" not in snapshot
    logs = machine.succeed("journalctl -u proton-pass-producer -u proton-pass-delivery --no-pager")
    assert "fixture-master-token" not in logs and "fixture-hidden-value-alpha" not in logs
    # A local edit is never overwritten by unattended delivery.
    machine.succeed("su - alice -c 'echo local-edit > ~/.password-store/compiler-service/production/token.gpg'")
    machine.fail("systemctl start proton-pass-delivery.service")
    assert machine.succeed("su - alice -c 'cat ~/.password-store/compiler-service/production/token.gpg'").strip() == "local-edit"
    # Tampered and absent master credentials fail closed.
    machine.succeed("cp /etc/credstore.encrypted/proton-token /root/good-token; echo corrupt > /etc/credstore.encrypted/proton-token")
    machine.fail("systemctl start proton-pass-producer.service")
    machine.succeed("rm /etc/credstore.encrypted/proton-token")
    machine.fail("systemctl start proton-pass-producer.service")
    machine.succeed("mv /root/good-token /etc/credstore.encrypted/proton-token")
    # Repeated scheduler ticks in one human session do not retry immediately.
    machine.succeed("systemctl reset-failed proton-pass-producer proton-pass-delivery")
    machine.fail("systemctl start proton-pass-schedule.service")  # delivery conflict
    stamp = machine.succeed("cat /var/lib/proton-pass-schedule/attempt")
    machine.succeed("systemctl start proton-pass-schedule.service")
    assert machine.succeed("cat /var/lib/proton-pass-schedule/attempt") == stamp
    # A lingering manager or closing session is not a human login.
    machine.succeed("systemctl stop getty@tty1.service serial-getty@ttyS0.service")
    machine.succeed("loginctl enable-linger alice; loginctl terminate-user alice")
    machine.succeed("echo 0 > /var/lib/proton-pass-schedule/attempt")
    machine.succeed("systemctl start proton-pass-schedule.service")
    assert machine.succeed("cat /var/lib/proton-pass-schedule/attempt").strip() == "0"
  '';
}
