# nftables firewall — OPNSense-equivalent default ruleset.
#
# Design goals (matching OPNSense defaults):
#   - Default deny inbound on WAN
#   - Allow all outbound from LAN (non-web via WAN, web via WARP)
#   - Stateful connection tracking (allow established/related)
#   - Anti-spoof on WAN (bogon sets for v4 + v6)
#   - ICMP/ICMPv6 rate limiting
#   - Kill switch: web traffic dropped if WARP tunnel is down
#   - NAT (masquerade) for LAN → WAN and LAN → WARP
#   - IPv6 forwarding blocked (NAT/WARP are IPv4-only)
{ config, lib, pkgs, ... }:

{
  # Disable NixOS's built-in iptables firewall — we use raw nftables
  networking.firewall.enable = false;

  # ── Kernel hardening (OPNSense defaults) ────────────────────────────
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv4.conf.all.forwarding" = 1;
    # IPv6 forwarding DISABLED — NAT and WARP are IPv4-only.
    "net.ipv6.conf.all.forwarding" = 0;

    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;
    "net.ipv4.conf.all.log_martians" = 1;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.tcp_rfc1337" = 1;

    # Conntrack tuning — safe defaults for 4GB+ RAM routers
    "net.netfilter.nf_conntrack_max" = 524288;
    "net.netfilter.nf_conntrack_tcp_timeout_established" = 7200;
    "net.netfilter.nf_conntrack_udp_timeout_stream" = 120;
    # nf_conntrack_buckets is auto-sized from nf_conntrack_max by the kernel
    # and is read-only on most configurations — don't set it via sysctl

    # Network buffer tuning — helps with burst traffic
    "net.core.rmem_max" = 16777216;
    "net.core.wmem_max" = 16777216;
    "net.core.rmem_default" = 1048576;
    "net.core.wmem_default" = 1048576;
    "net.ipv4.tcp_rmem" = "4096 1048576 16777216";
    "net.ipv4.tcp_wmem" = "4096 1048576 16777216";

    # Increase backlog for bursty traffic
    "net.core.netdev_max_backlog" = 8192;
    "net.core.somaxconn" = 4096;

    # Don't accept IPv6 router advertisements
    "net.ipv6.conf.all.accept_ra" = 0;
    "net.ipv6.conf.default.accept_ra" = 0;
  };

  networking.nftables = {
    enable = true;
    ruleset = ''
      table inet filter {
        # ── Sets ──────────────────────────────────────────────────────
        set bogons_v4 {
          type ipv4_addr
          flags interval
          elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.0.0.0/24,
            192.0.2.0/24,
            192.168.0.0/16,
            198.18.0.0/15,
            198.51.100.0/24,
            203.0.113.0/24,
            224.0.0.0/3
          }
        }

        set bogons_v6 {
          type ipv6_addr
          flags interval
          elements = {
            ::1/128,
            ::/128,
            ::ffff:0:0/96,
            100::/64,
            fc00::/7,
            fe80::/10,
            2001:db8::/32,
            2001::/23
          }
        }

        set rate_limit_icmp {
          type ipv4_addr
          flags dynamic,timeout
          timeout 10s
        }

        set rate_limit_icmpv6 {
          type ipv6_addr
          flags dynamic,timeout
          timeout 10s
        }

        # ── Base chains ───────────────────────────────────────────────
        chain input {
          type filter hook input priority filter; policy drop;

          # Loopback
          iifname "lo" accept

          # Connection tracking — allow established/related, drop invalid
          ct state established,related accept
          ct state invalid drop

          # ── WAN input ──────────────────────────────────────────────
          iifname "wan0" jump wan_input

          # ── LAN input (to the firewall itself) ─────────────────────
          iifname "br-lan" jump lan_input

          # Fallback log + drop
          limit rate 10/second burst 50 packets log prefix "[nft-input-drop] "
          drop
        }

        chain forward {
          type filter hook forward priority filter; policy drop;

          # Connection tracking
          ct state established,related accept
          ct state invalid drop

          # Block all IPv6 forwarding — NAT and WARP are IPv4-only
          meta nfproto ipv6 drop

          # ── LAN → LAN: local traffic between clients (and future VLANs) ──
          iifname "br-lan" oifname "br-lan" accept

          # ── Kill switch: LAN traffic must not leave unencrypted ──
          # Block bare WAN so no traffic leaks without VPN protection.
          # wg-mullvad is allowed — it's a VPN tunnel, not a leak.  WARP
          # excludes some IPs from its tunnel (Apple, etc.) and during any
          # WARP reconnect all traffic briefly falls through to wg-mullvad
          # via the main routing table.  Blocking it would blackhole LAN.
          iifname "br-lan" oifname "wan0" limit rate 10/second burst 50 packets log prefix "[nft-warp-leak] "
          iifname "br-lan" oifname "wan0" drop

          # LAN → Mullvad: VPN-protected fallback
          iifname "br-lan" oifname "wg-mullvad" accept

          # LAN → WARP: all internet traffic
          iifname "br-lan" oifname "CloudflareWARP" accept

          limit rate 10/second burst 50 packets log prefix "[nft-forward-drop] "
          drop
        }

        chain output {
          type filter hook output priority filter; policy accept;
          # Firewall itself is trusted — allow all outbound
        }

        # ── WAN input rules ───────────────────────────────────────────
        chain wan_input {
          # Drop bogon source IPs (anti-spoof)
          ip saddr @bogons_v4 drop
          ip6 saddr @bogons_v6 drop

          # ICMP: allow ping with rate limit
          ip protocol icmp icmp type echo-request \
            add @rate_limit_icmp { ip saddr limit rate 5/second burst 10 packets } accept
          ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept

          # ICMPv6: essential types with rate limiting on echo-request
          ip6 nexthdr icmpv6 icmpv6 type echo-request \
            add @rate_limit_icmpv6 { ip6 saddr limit rate 5/second burst 10 packets } accept
          ip6 nexthdr icmpv6 icmpv6 type {
            destination-unreachable, packet-too-big, time-exceeded,
            parameter-problem, echo-reply,
            nd-router-solicit, nd-router-advert,
            nd-neighbor-solicit, nd-neighbor-advert
          } accept

          # DHCP client (for WAN DHCP)
          udp sport 67 udp dport 68 accept

          # Everything else on WAN: drop (default deny)
          drop
        }

        # ── LAN input rules ───────────────────────────────────────────
        chain lan_input {
          # Allow DNS to this box (we run unbound)
          udp dport 53 accept
          tcp dport 53 accept

          # Allow DHCP
          udp sport 68 udp dport 67 accept

          # Allow SSH from LAN
          tcp dport 22 accept

          # Allow ICMP from LAN
          ip protocol icmp accept
          ip6 nexthdr icmpv6 accept

          # Drop anything else to the firewall from LAN
          limit rate 10/second burst 50 packets log prefix "[nft-lan-input-drop] "
          drop
        }
      }

      # ── NAT ───────────────────────────────────────────────────────────
      table ip nat {
        chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;

          # Force all LAN DNS through Unbound — ignores client-configured resolvers
          # (e.g., 8.8.8.8, 9.9.9.9). Excludes queries already aimed at the firewall.
          iifname "br-lan" ip daddr != 192.168.1.1 udp dport 53 dnat to 192.168.1.1:53
          iifname "br-lan" ip daddr != 192.168.1.1 tcp dport 53 dnat to 192.168.1.1:53

          # Port forwards go here, e.g.:
          # iifname "wan0" tcp dport 8080 dnat to 10.0.1.100:80
        }

        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;

          # Masquerade LAN traffic going out WAN
          oifname "wan0" masquerade

          # Masquerade LAN traffic going out WARP tunnel
          oifname "CloudflareWARP" masquerade

          # Masquerade traffic going out Mullvad tunnel
          oifname "wg-mullvad" masquerade
        }
      }
    '';
  };
}
