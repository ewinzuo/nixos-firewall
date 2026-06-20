# sops-nix secrets management — decrypts secrets at activation time.
#
# The age decryption key is derived from the host's SSH ed25519 key
# (ssh-to-age), so no separate key file is needed.
#
# Setup (one-time, on the deployed firewall):
#   1. Get the host's age pubkey:
#        ssh root@firewall "cat /etc/ssh/ssh_host_ed25519_key.pub" | ssh-to-age
#   2. Add that pubkey to .sops.yaml under &firewall_prod
#   3. Encrypt the Mullvad private key:
#        sops secrets/mullvad.yaml
#   4. Deploy: nixos-rebuild switch --flake .#firewall --target-host root@firewall
{ config, lib, ... }:

{
  # Derive the age key from the host's SSH ed25519 key — no separate
  # key file to manage, rotate, or lose.
  sops.age.sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];

  # The Mullvad WireGuard private key, decrypted to tmpfs at boot.
  sops.secrets.mullvad-private-key = {
    owner = "root";
    group = "root";
    mode = "0600";
    key = "mullvad-private-key";
  };

  # Point mullvad.nix at the sops-managed path (tmpfs, decrypted at boot)
  firewall.mullvad.privateKeyFile = config.sops.secrets.mullvad-private-key.path;
}
