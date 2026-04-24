# NixOS integration test for the firewall config.
#
# Spins up three QEMU VMs:
#   - "firewall": runs the production modules unchanged
#   - "client":   a LAN machine behind the firewall
#   - "wan":      a simulated upstream / "the internet"
#
# Run with: nix build .#checks.x86_64-linux.firewall-test -L
#
# How drift is avoided: QEMU's eth1/eth2 are renamed to wan0/lan1 via
# `OriginalName` link matching, so production's network, firewall, and
# DHCP/DNS modules apply with their real interface names and IPs. Only
# the WAN subnet (test-only) and a static wan0 address (no upstream DHCP)
# are overridden — everything else comes from the real configuration.
{ nixpkgs, ... }:

let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
in
pkgs.testers.nixosTest {
  name = "firewall-integration";

  nodes = {
    # ── The firewall/router (production modules, unchanged rules) ─────
    firewall = { config, pkgs, lib, ... }: {
      environment.systemPackages = [ pkgs.dnsutils pkgs.nftables pkgs.netcat-gnu ];

      imports = [
        ../modules/options.nix
        ../modules/network.nix
        ../modules/firewall.nix
        ../modules/dhcp-dns.nix
        # warp.nix / mullvad.nix not imported — they need live internet.
        # The CloudflareWARP / wg-mullvad interfaces simply don't exist;
        # the production kill switch (drop br-lan → wan0) makes the
        # missing tunnels visible by blocking all forwarded traffic.
      ];

      # In NixOS test VMs eth0 is the management interface, and
      # `vlans = [ 1 2 ]` brings up eth1 (vlan1) and eth2 (vlan2).
      # Rename them to production names so the production network and
      # firewall modules apply unchanged.
      systemd.network.links = lib.mkForce {
        "10-wan0" = {
          matchConfig.OriginalName = "eth1";
          linkConfig.Name = "wan0";
        };
        "10-lan1" = {
          matchConfig.OriginalName = "eth2";
          linkConfig.Name = "lan1";
        };
      };

      # Production wan0 uses DHCP from the ISP; the test has no upstream
      # DHCP server, so override only this network with a static address.
      # Everything else (br-lan bridge, lan1 enslavement) comes from
      # modules/network.nix.
      systemd.network.networks."20-wan0" = lib.mkForce {
        matchConfig.Name = "wan0";
        networkConfig.Address = "1.2.3.2/24";
        linkConfig.RequiredForOnline = "no";
      };

      virtualisation.vlans = [ 1 2 ];   # eth1 = vlan1 (WAN), eth2 = vlan2 (LAN)
    };

    # ── LAN client ─────────────────────────────────────────────────────
    client = { config, pkgs, lib, ... }: {
      systemd.network.enable = true;
      networking.useDHCP = false;

      systemd.network.networks."20-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
        dhcpV4Config.UseDNS = true;
      };

      environment.systemPackages = [ pkgs.curl pkgs.dnsutils pkgs.netcat-gnu ];

      virtualisation.vlans = [ 2 ];  # Same VLAN as firewall's LAN
    };

    # ── WAN simulator (acts as "the internet") ─────────────────────────
    wan = { config, pkgs, lib, ... }: {
      networking.firewall.allowedTCPPorts = [ 80 8080 ];
      systemd.network.enable = true;
      networking.useDHCP = false;

      systemd.network.networks."20-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.Address = "1.2.3.1/24";
      };

      systemd.services.test-httpd = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80";
          Type = "simple";
        };
      };
      systemd.services.test-httpd-alt = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080";
          Type = "simple";
        };
      };

      boot.kernel.sysctl."net.ipv4.ip_forward" = 0;

      virtualisation.vlans = [ 1 ];  # Same VLAN as firewall's WAN
    };
  };

  testScript = ''
    start_all()

    # ── Test 1: Firewall boots; production-named interfaces are up ────
    firewall.wait_for_unit("systemd-networkd.service")
    firewall.wait_for_unit("multi-user.target")
    firewall.succeed("ip addr show wan0 | grep '1.2.3.2'")
    firewall.succeed("ip addr show br-lan | grep '192.168.1.1'")

    # ── Test 2: Production nftables ruleset is loaded as-is ───────────
    firewall.succeed("nft list ruleset | grep 'chain input'")
    firewall.succeed("nft list ruleset | grep 'chain wan_input'")
    firewall.succeed("nft list ruleset | grep 'chain lan_input'")
    firewall.succeed("nft list ruleset | grep 'masquerade'")
    firewall.succeed("nft list ruleset | grep 'bogons_v4'")
    # Kill switch references real production interface names
    firewall.succeed("nft list ruleset | grep -F 'iifname \"br-lan\" oifname \"wan0\"'")

    # ── Test 3: Kea DHCP is running on production subnet ──────────────
    firewall.wait_for_unit("kea-dhcp4-server.service")

    # ── Test 4: Unbound DNS is running with production local-data ─────
    firewall.wait_for_unit("unbound.service")
    firewall.succeed("dig @127.0.0.1 firewall.lan.home A +short | grep '192.168.1.1'")

    # ── Test 5: LAN client gets a 192.168.1.x DHCP lease ──────────────
    client.wait_for_unit("systemd-networkd.service")
    client.wait_until_succeeds("ip addr show eth1 | grep '192.168.1.'", timeout=30)

    # ── Test 6: Client can reach the firewall ─────────────────────────
    client.succeed("ping -c 2 -W 3 192.168.1.1")

    # ── Test 7: Client can resolve DNS through the firewall ───────────
    client.succeed("dig @192.168.1.1 firewall.lan.home A +short | grep '192.168.1.1'")

    # ── Test 8: DNS forcing — queries to external resolvers are DNATed ─
    # Production redirects all br-lan DNS to 192.168.1.1; a query aimed
    # at 8.8.8.8 must still be answered by Unbound.
    client.succeed("dig @8.8.8.8 firewall.lan.home A +short | grep '192.168.1.1'")

    # ── Test 9: IP forwarding is enabled ──────────────────────────────
    firewall.succeed("sysctl net.ipv4.ip_forward | grep '= 1'")

    # ── Test 10: Kill switch — bare WAN forwarding is dropped ─────────
    # Production drops every br-lan → wan0 packet (must go via WARP /
    # wg-mullvad, neither of which exists in this offline test). So
    # web AND non-web LAN→WAN must all fail.
    wan.wait_for_unit("test-httpd.service")
    wan.wait_for_unit("test-httpd-alt.service")
    client.fail("curl -sf --max-time 5 http://1.2.3.1:80")
    client.fail("curl -sf --max-time 5 http://1.2.3.1:8080")
    client.fail("nc -z -w 3 1.2.3.1 443")

    # ── Test 11: WAN inbound to firewall is blocked (default deny) ────
    wan.fail("nc -z -w 3 1.2.3.2 22")

    # ── Test 12: Bogon set contains expected entries ──────────────────
    firewall.succeed("nft list set inet filter bogons_v4 | grep '172.16.0.0/12'")

    # ── Test 13: Kernel hardening sysctls (from production) ───────────
    firewall.succeed("sysctl net.ipv4.conf.all.rp_filter | grep '= 1'")
    firewall.succeed("sysctl net.ipv4.tcp_syncookies | grep '= 1'")
    firewall.succeed("sysctl net.ipv4.conf.all.accept_redirects | grep '= 0'")

    # ── Test 14: IPv6 forwarding is disabled ──────────────────────────
    firewall.succeed("sysctl net.ipv6.conf.all.forwarding | grep '= 0'")

    # ── Test 15: Log rate limiting is configured ──────────────────────
    firewall.succeed("nft list ruleset | grep 'limit rate 10/second'")
  '';
}
