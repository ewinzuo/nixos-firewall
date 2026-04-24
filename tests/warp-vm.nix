# Standalone VM for live-testing the full firewall stack with WARP + MASQUE.
#
# Build:  nix build .#warp-test-vm
# Run:    ./result/bin/run-warp-test-vm
#
# Topology: single SLIRP NIC. We rename eth0 → wan0 so the production
# firewall, network, and dhcp-dns modules apply with their real
# interface names; only the things SLIRP/single-NIC topology can't
# provide (no LAN bridge, no upstream DHCP server we control) are
# overridden.
#
# Once booted, log in as root (no password) and run:
#   /etc/setup-warp.sh        # register + connect (once)
#   /etc/test-warp-live.sh    # run integration tests
{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [
    ../configuration.nix
    ../modules/options.nix
    ../modules/network.nix
    ../modules/firewall.nix
    ../modules/dhcp-dns.nix
    ../modules/warp.nix
  ];

  # ── VM basics ──────────────────────────────────────────────────────
  users.users.root.initialPassword = "";
  services.getty.autologinUser = "root";
  networking.hostName = lib.mkForce "warp-test-vm";

  # ── VM overrides for configuration.nix incompatibilities ───────────
  # QEMU VMs load the kernel directly — no bootloader needed
  boot.loader.systemd-boot.enable = lib.mkForce false;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  # SSH: listen on all interfaces and allow root (192.168.1.1 doesn't exist in VM)
  services.openssh.listenAddresses = lib.mkForce [ ];
  services.openssh.settings.PermitRootLogin = lib.mkForce "yes";
  # No hardware watchdog in QEMU
  systemd.watchdog = lib.mkForce { };

  # ── Rename SLIRP eth0 → wan0 so production rules apply unchanged ───
  systemd.network.links = lib.mkForce {
    "10-wan0" = {
      matchConfig.OriginalName = "eth0";
      linkConfig.Name = "wan0";
    };
  };

  # SLIRP gives DHCP — production wants DHCP on wan0 too, so we just
  # let it through. The bridge / lan* networks from production have no
  # matching interfaces and are silently inert.
  systemd.network.networks."20-wan0" = lib.mkForce {
    matchConfig.Name = "wan0";
    networkConfig.DHCP = "ipv4";
    dhcpV4Config = {
      UseDNS = false;
      UseRoutes = true;
      RouteMetric = 100;
    };
    linkConfig.RequiredForOnline = "routable";
  };

  # No physical LAN — drop the br-lan requirement so boot doesn't stall
  systemd.network.networks."20-br-lan" = lib.mkForce {
    matchConfig.Name = "br-lan";
    networkConfig = {
      Address = "192.168.1.1/24";
      KeepConfiguration = "static";
    };
    linkConfig.RequiredForOnline = "no";
  };

  # Unbound: no LAN to serve, listen on localhost only
  services.unbound.settings.server.interface = lib.mkForce [ "127.0.0.1" ];
  services.unbound.settings.server.access-control = lib.mkForce [
    "127.0.0.0/8 allow"
  ];

  # Kea: no LAN clients to lease to
  services.kea.dhcp4.enable = lib.mkForce false;

  # ── Loosen rp_filter for SLIRP (10.0.2.x is a bogon-looking range) ─
  boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = lib.mkForce 0;

  # Extra packages on top of configuration.nix's list
  environment.systemPackages = with pkgs; [
    curl
    iproute2
    iputils
  ];

  # Copy test scripts into the VM
  environment.etc."setup-warp.sh" = {
    source = ../setup-warp.sh;
    mode = "0755";
  };
  environment.etc."test-warp-live.sh" = {
    source = ./test-warp-live.sh;
    mode = "0755";
  };
  environment.etc."test-client-routing.sh" = {
    source = ./test-client-routing.sh;
    mode = "0755";
  };

  environment.etc."motd".text = ''

    ╔══════════════════════════════════════════════════════╗
    ║  WARP Test VM (full stack)                          ║
    ║                                                     ║
    ║  1. /etc/setup-warp.sh          (register + connect)║
    ║  2. /etc/test-warp-live.sh      (WARP tests)        ║
    ║  3. /etc/test-client-routing.sh (client E2E test)   ║
    ╚══════════════════════════════════════════════════════╝

  '';

  boot.kernelParams = [ "console=ttyS0,115200" ];

  virtualisation = {
    memorySize = 2048;
    cores = 2;
    diskSize = 4096;
    graphics = false;
    forwardPorts = [
      { from = "host"; host.port = 2222; guest.port = 22; }
    ];
  };
}
