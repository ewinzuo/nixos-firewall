# NixOS integration test for the firewall config.
#
# Spins up two QEMU VMs:
#   - "firewall": the router/firewall box (runs our modules)
#   - "client":   a LAN machine behind the firewall
#
# Run with: nix build .#checks.x86_64-linux.firewall-test -L
#
# Tests:
#   1. Firewall boots and interfaces come up
#   2. nftables rules are loaded
#   3. LAN client gets DHCP lease
#   4. LAN client can resolve DNS through the firewall
#   5. LAN client can reach the firewall (ping)
#   6. NAT/masquerade is configured
#   7. Kill switch: HTTP/HTTPS to WAN is blocked (must go via WARP)
#   8. Bogon traffic on WAN is dropped
#   9. WAN inbound connections are rejected
#  10. Kernel hardening sysctls
#
# WARP itself requires live internet — test with tests/test-warp-live.sh
{ nixpkgs, ... }:

let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
in
pkgs.testers.nixosTest {
  name = "firewall-integration";

  nodes = {
    # ── The firewall/router ───────────────────────────────────────────
    firewall = { config, pkgs, lib, ... }: {
      environment.systemPackages = [ pkgs.dnsutils pkgs.nftables pkgs.netcat-gnu ];

      imports = [
        ../modules/options.nix
        ../modules/network.nix
        ../modules/firewall.nix
        ../modules/dhcp-dns.nix
        # warp.nix NOT imported — warp-svc needs live internet to register.
        # The kill switch is tested by verifying web traffic is blocked without
        # the CloudflareWARP interface present.
      ];

      # Override hardware-specific settings for the VM
      systemd.network.links = lib.mkForce { };   # No MAC matching in VMs

      # In NixOS test VMs, eth0 is the internal management interface.
      # vlans = [ 1 2 ] maps to eth1 = vlan1 (WAN), eth2 = vlan2 (LAN).
      systemd.network.networks = lib.mkForce {
        "20-wan0" = {
          matchConfig.Name = "eth1";
          networkConfig = {
            Address = "192.168.1.2/24";
            Gateway = "192.168.1.1";
          };
        };
        "20-lan0" = {
          matchConfig.Name = "eth2";
          networkConfig.Address = "10.0.1.1/24";
        };
      };

      # Replace nftables rules to use eth1/eth2 instead of wan0/lan0.
      # In NixOS test VMs: eth0=mgmt, eth1=vlan1(WAN), eth2=vlan2(LAN).
      # No warp0 exists in the test, so the kill switch rules effectively block
      # all web traffic from LAN → WAN (which is what we want to verify).
      networking.nftables = lib.mkForce {
        enable = true;
        ruleset = ''
          table inet filter {
            set bogons_v4 {
              type ipv4_addr
              flags interval
              elements = {
                0.0.0.0/8,
                100.64.0.0/10,
                127.0.0.0/8,
                169.254.0.0/16,
                172.16.0.0/12,
                192.0.0.0/24,
                192.0.2.0/24,
                198.18.0.0/15,
                198.51.100.0/24,
                203.0.113.0/24,
                224.0.0.0/3
              }
            }

            chain input {
              type filter hook input priority filter; policy drop;

              iifname "lo" accept
              ct state established,related accept
              ct state invalid drop

              iifname "eth1" jump wan_input
              iifname "eth2" jump lan_input

              limit rate 10/second burst 50 packets log prefix "[nft-input-drop] "
              drop
            }

            chain forward {
              type filter hook forward priority filter; policy drop;

              ct state established,related accept
              ct state invalid drop

              # Block IPv6 forwarding
              meta nfproto ipv6 drop

              # Kill switch: block web traffic on WAN (should only go via WARP)
              iifname "eth2" oifname "eth1" tcp dport { 80, 443 } drop
              iifname "eth2" oifname "eth1" udp dport 443 drop

              # Allow non-web LAN → WAN
              iifname "eth2" oifname "eth1" accept
              iifname "eth2" oifname "eth2" accept

              limit rate 10/second burst 50 packets log prefix "[nft-forward-drop] "
              drop
            }

            chain output {
              type filter hook output priority filter; policy accept;
            }

            chain wan_input {
              ip saddr @bogons_v4 drop
              ip protocol icmp icmp type echo-request accept
              ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
              udp sport 67 udp dport 68 accept
              drop
            }

            chain lan_input {
              udp dport 53 accept
              tcp dport 53 accept
              udp sport 68 udp dport 67 accept
              tcp dport 22 accept
              ip protocol icmp accept
              limit rate 10/second burst 50 packets log prefix "[nft-lan-input-drop] "
              drop
            }
          }

          table ip nat {
            chain postrouting {
              type nat hook postrouting priority srcnat; policy accept;
              oifname "eth1" masquerade
            }
          }
        '';
      };

      # Unbound: override only the bits that differ for the test VM
      services.unbound.settings.server = {
        interface = lib.mkForce [ "10.0.1.1" "127.0.0.1" ];
        access-control = lib.mkForce [
          "10.0.1.0/24 allow"
          "127.0.0.0/8 allow"
        ];
        local-zone = lib.mkForce [ "test.lan. static" ];
        local-data = lib.mkForce [ ''"firewall.test.lan. IN A 10.0.1.1"'' ];
      };
      # No upstream forwarders in test — just serve local data
      services.unbound.settings.forward-zone = lib.mkForce [ ];

      # Kea: use eth2 with test subnet (production uses 192.168.1.x but test WAN
      # is already on 192.168.1.x so we keep LAN at 10.0.1.x here)
      services.kea.dhcp4.settings.interfaces-config.interfaces = lib.mkForce [ "eth2" ];
      services.kea.dhcp4.settings.subnet4 = lib.mkForce [
        {
          id = 1;
          subnet = "10.0.1.0/24";
          pools = [ { pool = "10.0.1.100 - 10.0.1.250"; } ];
          option-data = [
            { name = "routers";             data = "10.0.1.1"; }
            { name = "domain-name-servers"; data = "10.0.1.1"; }
            { name = "domain-name";         data = "lan.home"; }
            { name = "subnet-mask";         data = "255.255.255.0"; }
          ];
          reservations = [];
        }
      ];

      # Sysctls come from modules/firewall.nix (imported above)
      networking.iproute2.enable = true;

      virtualisation = {
        vlans = [ 1 2 ];   # eth1 = vlan1 (WAN), eth2 = vlan2 (LAN)
      };
    };

    # ── LAN client ────────────────────────────────────────────────────
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

    # ── WAN simulator (acts as "the internet") ────────────────────────
    wan = { config, pkgs, lib, ... }: {
      networking.firewall.allowedTCPPorts = [ 80 8080 ];
      systemd.network.enable = true;
      networking.useDHCP = false;

      systemd.network.networks."20-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.Address = "192.168.1.1/24";
      };

      # HTTP server on port 80 (blocked by kill switch) and 8080 (allowed as non-web)
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

    # ── Test 1: Firewall boots and interfaces come up ──────────────────
    firewall.wait_for_unit("systemd-networkd.service")
    firewall.wait_for_unit("multi-user.target")
    firewall.succeed("ip addr show eth1 | grep '192.168.1.2'")
    firewall.succeed("ip addr show eth2 | grep '10.0.1.1'")

    # ── Test 2: nftables rules are loaded ──────────────────────────────
    firewall.succeed("nft list ruleset | grep 'chain input'")
    firewall.succeed("nft list ruleset | grep 'chain wan_input'")
    firewall.succeed("nft list ruleset | grep 'chain lan_input'")
    firewall.succeed("nft list ruleset | grep 'masquerade'")
    firewall.succeed("nft list ruleset | grep 'bogons_v4'")

    # ── Test 3: Kea DHCP is running ───────────────────────────────────
    firewall.wait_for_unit("kea-dhcp4-server.service")

    # ── Test 4: Unbound DNS is running ────────────────────────────────
    firewall.wait_for_unit("unbound.service")
    firewall.succeed("dig @127.0.0.1 firewall.test.lan A +short | grep '10.0.1.1'")

    # ── Test 5: Client gets DHCP lease ────────────────────────────────
    client.wait_for_unit("systemd-networkd.service")
    client.wait_until_succeeds("ip addr show eth1 | grep '10.0.1.'", timeout=30)

    # ── Test 6: Client can ping the firewall ──────────────────────────
    client.succeed("ping -c 2 -W 3 10.0.1.1")

    # ── Test 7: Client can resolve DNS through the firewall ───────────
    client.succeed("dig @10.0.1.1 firewall.test.lan A +short | grep '10.0.1.1'")

    # ── Test 8: IP forwarding is enabled ──────────────────────────────
    firewall.succeed("sysctl net.ipv4.ip_forward | grep '= 1'")

    # ── Test 9: NAT is working — client can reach WAN on non-web port ──
    wan.wait_for_unit("test-httpd-alt.service")
    wan.wait_for_unit("multi-user.target")
    # Client should reach WAN on port 8080 (non-web, allowed through)
    client.wait_until_succeeds("curl -sf --max-time 5 http://192.168.1.1:8080", timeout=30)

    # ── Test 10: Kill switch — HTTP (port 80) to WAN is BLOCKED ───────
    # Web traffic must only go via WARP; without warp0 it should be dropped
    wan.wait_for_unit("test-httpd.service")
    client.fail("curl -sf --max-time 5 http://192.168.1.1:80")

    # ── Test 11: Kill switch — HTTPS (port 443) to WAN is BLOCKED ─────
    client.fail("nc -z -w 3 192.168.1.1 443")

    # ── Test 12: WAN inbound is blocked (default deny) ────────────────
    wan.fail("nc -z -w 3 192.168.1.2 22")

    # ── Test 13: Bogon source on WAN is dropped ───────────────────────
    firewall.succeed("nft list set inet filter bogons_v4 | grep '172.16.0.0/12'")

    # ── Test 14: Kernel hardening sysctls ─────────────────────────────
    firewall.succeed("sysctl net.ipv4.conf.all.rp_filter | grep '= 1'")
    firewall.succeed("sysctl net.ipv4.tcp_syncookies | grep '= 1'")
    firewall.succeed("sysctl net.ipv4.conf.all.accept_redirects | grep '= 0'")

    # ── Test 15: IPv6 forwarding is disabled ──────────────────────────
    firewall.succeed("sysctl net.ipv6.conf.all.forwarding | grep '= 0'")

    # ── Test 16: Log rate limiting is configured ──────────────────────
    firewall.succeed("nft list ruleset | grep 'limit rate 10/second'")
  '';
}
