# E2E client VM — a plain LAN host sitting behind the firewall on vlan2.
#
# NIC layout (set by tests/e2e/run-e2e.sh QEMU launch flags):
#   eth0 = mgmt slirp     — SSH access from host (10.0.2.0/24, no default route)
#   eth1 = vlan2 socket   — the "LAN cable"; gets DHCP from the firewall (Kea)
#
# This VM is intentionally minimal: it does NOT import any production module.
# Its job is to behave like a real laptop on the LAN — DHCP a 192.168.1.x
# lease, then let the test driver poke at curl/dig/nc to verify that the
# double tunnel is the only path to the internet (and that the kill switch
# blocks everything else).
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
  networking.hostName = "e2e-client";
  services.getty.autologinUser = "root";

  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";
  users.users.root.openssh.authorizedKeys.keys = [ runnerPubkey ];

  # ── Networking ─────────────────────────────────────────────────────
  networking.useDHCP = false;
  networking.useNetworkd = true;
  systemd.network.enable = true;

  # eth0 = mgmt slirp. DHCP for the IP, but no default route — we want
  # all "real" traffic to leave via eth1 → firewall LAN.
  systemd.network.networks."05-mgmt" = {
    matchConfig.Name = "eth0";
    networkConfig.DHCP = "ipv4";
    dhcpV4Config = {
      UseRoutes = false;
      UseDNS = false;
      UseHostname = false;
    };
    linkConfig.RequiredForOnline = "no";
  };

  # eth1 = "LAN cable" into the firewall's br-lan. Full DHCP (gateway +
  # DNS) so this VM behaves like a real LAN host.
  systemd.network.networks."20-lan" = {
    matchConfig.Name = "eth1";
    networkConfig.DHCP = "ipv4";
    dhcpV4Config = {
      UseRoutes = true;
      UseDNS = true;
    };
    linkConfig.RequiredForOnline = "routable";
  };

  # ── Convenience packages for the test driver ───────────────────────
  environment.systemPackages = with pkgs; [
    curl
    dnsutils
    iproute2
    iputils
    netcat-gnu
    tcpdump
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
      { from = "host"; host.port = 2223; guest.port = 22; }
    ];
  };
}
