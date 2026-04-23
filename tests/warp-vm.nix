# Standalone VM for live-testing the full firewall stack with WARP + MASQUE.
#
# Build:  nix build .#warp-test-vm
# Run:    ./result/bin/run-warp-test-vm-vm
#
# The VM boots with user-mode networking (SLIRP) so it has internet
# access through the host. Once booted, log in as root (no password)
# and run:
#   /etc/setup-warp.sh        # register + connect (once)
#   /etc/test-warp-live.sh    # run integration tests
{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [
    ../configuration.nix
    ../modules/options.nix
    ../modules/firewall.nix
    ../modules/dhcp-dns.nix
    ../modules/network.nix
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

  # ── Single-NIC overrides ───────────────────────────────────────────
  # SLIRP gives us eth0 (10.0.2.x). We treat it as WAN.
  # No physical LAN in the VM — Kea/Unbound still start but aren't used.
  networking.useDHCP = lib.mkForce true;
  systemd.network.enable = lib.mkForce false;
  systemd.network.links = lib.mkForce { };
  systemd.network.networks = lib.mkForce { };

  # Unbound: listen on localhost only (no lan0 in the VM)
  services.unbound.settings.server.interface = lib.mkForce [ "127.0.0.1" ];
  services.unbound.settings.server.access-control = lib.mkForce [
    "127.0.0.0/8 allow"
  ];

  # Kea: disable in the VM (no LAN clients)
  services.kea.dhcp4.enable = lib.mkForce false;

  # ── nftables: full production rules adapted for single-NIC VM ──────
  # eth0 = WAN equivalent. Kill switch blocks web traffic on eth0.
  # When WARP is connected, warp-svc routes web traffic via CloudflareWARP.
  # When WARP is disconnected, web traffic tries eth0 and gets killed.
  networking.nftables.ruleset = lib.mkForce ''
    table inet filter {
      chain input {
        type filter hook input priority filter; policy drop;

        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop

        # Allow DHCP (SLIRP)
        udp sport 67 udp dport 68 accept

        # Allow DNS, SSH, ICMP on all interfaces (test VM)
        udp dport 53 accept
        tcp dport 53 accept
        tcp dport 22 accept
        ip protocol icmp accept

        limit rate 10/second burst 50 packets log prefix "[nft-input-drop] "
        drop
      }

      chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        meta nfproto ipv6 drop

        # Kill switch: block web traffic on eth0 (WAN)
        # This is the critical rule — web must go through CloudflareWARP
        oifname "eth0" tcp dport { 80, 443 } drop
        oifname "eth0" udp dport 443 drop

        drop
      }

      chain output {
        type filter hook output priority filter; policy accept;
        # Firewall itself is trusted — allow all outbound
      }
    }

    table ip nat {
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
        oifname "CloudflareWARP" masquerade
      }
    }
  '';

  # ── Loosen rp_filter for SLIRP (10.0.2.x is technically a bogon) ──
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
