# E2E upstream VM — sits between the firewall's wan0 and the real internet.
#
# Two purposes:
#   1. NAT gateway — masquerades vlan1 traffic out eth0 (slirp) so the
#      firewall VM can reach Mullvad / WARP endpoints on the public internet.
#   2. Out-of-firewall observer — runs tcpdump on vlan1 to prove that the
#      ONLY thing leaving wan0 is encrypted WireGuard (UDP/51820), never a
#      bare LAN packet. This is the black-box proof that the kill switch
#      and double-tunnel are intact.
#
# NIC layout (set by tests/e2e/run-e2e.sh QEMU launch flags):
#   eth0 = slirp      — provides BOTH host SSH access AND real internet (NAT)
#   eth1 = vlan1      — point-to-point cable to the firewall's wan0
#                        (this VM = 10.99.0.1, firewall = 10.99.0.2)
#
# Note: unlike client/firewall, eth0 here KEEPS the slirp default route —
# that is how packets reach the public internet. The firewall, in turn,
# sends its WireGuard packets out wan0 → 10.99.0.1 → eth0 → real internet.
{ config, lib, pkgs, modulesPath, ... }:

let
  pubkeyPath = builtins.getEnv "E2E_SSH_PUBKEY_FILE";
  runnerPubkey =
    if pubkeyPath != "" && builtins.pathExists pubkeyPath
    then builtins.readFile pubkeyPath
    else throw ''
      Missing E2E_SSH_PUBKEY_FILE or its target.
      run-e2e.sh generates a runner keypair and exports this var.
    '';
in
{
  # ── VM identity & access ───────────────────────────────────────────
  networking.hostName = "e2e-upstream";
  services.getty.autologinUser = "root";

  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";
  users.users.root.openssh.authorizedKeys.keys = [ runnerPubkey ];

  # ── Networking ─────────────────────────────────────────────────────
  networking.useDHCP = false;
  networking.useNetworkd = true;
  systemd.network.enable = true;

  # eth0 = slirp. Keep its default route — this is our path to the
  # real internet, used both for SSH-from-host and for NAT-out.
  systemd.network.networks."05-slirp" = {
    matchConfig.Name = "eth0";
    networkConfig.DHCP = "ipv4";
    linkConfig.RequiredForOnline = "routable";
  };

  # eth1 = vlan1 cable to the firewall's wan0. Static IP — no DHCP
  # server here; the firewall is configured for static 10.99.0.2/24.
  systemd.network.networks."20-vlan1" = {
    matchConfig.Name = "eth1";
    networkConfig.Address = "10.99.0.1/24";
    linkConfig.RequiredForOnline = "no";
  };

  # ── Routing & NAT ──────────────────────────────────────────────────
  # Use the standard NixOS NAT module — masquerade vlan1 traffic as it
  # leaves eth0. This is what gives the firewall VM a real path to
  # Mullvad / WARP servers on the public internet.
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
  networking.nat = {
    enable = true;
    externalInterface = "eth0";
    internalInterfaces = [ "eth1" ];
  };

  # The host runner SSHes in over slirp and would otherwise be blocked
  # by NixOS's default firewall — open SSH and let everything else
  # through (this VM is a test-only NAT gateway, not a security boundary).
  networking.firewall.enable = false;

  # ── Convenience packages for the test driver ───────────────────────
  # tcpdump is the star of the show — the test driver runs it on eth1
  # to capture every packet the firewall emits and asserts that they
  # are all WireGuard.
  environment.systemPackages = with pkgs; [
    tcpdump
    iproute2
    iputils
    nftables
    jq
  ];

  # ── Boot/serial/QEMU knobs ─────────────────────────────────────────
  boot.kernelParams = [ "console=ttyS0,115200" ];

  virtualisation = {
    memorySize = 1024;
    cores = 1;
    diskSize = 4096;
    graphics = false;
    forwardPorts = [
      { from = "host"; host.port = 2224; guest.port = 22; }
    ];
  };
}
