# Cloudflare WARP via warp-svc — isolated in its own network namespace.
#
# Why netns:
#   warp-svc installs an ip-rule "not fwmark 0x100cf lookup 65743" at runtime
#   to capture all unmarked traffic into the CloudflareWARP tunnel. When the
#   daemon runs in the main netns, that rule applies to EVERYTHING on the
#   host — services that need bare-WAN egress (e.g. Plex's plex.tv signaling)
#   get rewritten, breaking remote access. Worse, the priority is dynamic;
#   we can't reliably beat it from outside the daemon.
#
#   Putting warp-svc in its own netns scopes ALL of WARP's runtime side-
#   effects (ip rules, routes, CloudflareWARP interface, kill-switch nft
#   tables) to that netns. The main netns stays clean. Other services
#   ignore WARP unless they explicitly opt in via NetworkNamespacePath.
#
# How services use WARP after this refactor:
#   Add `serviceConfig.NetworkNamespacePath = "/run/netns/warp"` to any
#   systemd service that should egress through WARP. Everything else uses
#   main netns routing (which routes through Mullvad or bare wan0
#   depending on fwmark).
#
# Daemon connectivity bootstrap:
#   The WARP daemon (in warpns) needs to reach Cloudflare's MASQUE
#   servers to establish the tunnel. A veth pair connects warpns ↔ main:
#     warpns side  : veth-warp (10.99.1.2/30), default route → 10.99.1.1
#     main side    : veth-warp-h (10.99.1.1/30)
#   Outbound from warpns gets NAT-masqueraded in main netns. The traffic
#   then enters main's routing chain (Mullvad takes it by default —
#   consistent with "WARP layered on Mullvad" design).
#
# Setup (run once on the deployed box):
#   sudo ./setup-warp.sh
#   — or manually inside the netns:
#   1. sudo ip netns exec warp warp-cli registration delete 2>/dev/null
#   2. sudo ip netns exec warp warp-cli --accept-tos registration new
#   3. sudo ip netns exec warp warp-cli mode tunnel_only
#   4. sudo ip netns exec warp warp-cli tunnel protocol set MASQUE
#   5. sudo ip netns exec warp warp-cli connect
#   6. Verify: sudo ip netns exec warp curl -s https://www.cloudflare.com/cdn-cgi/trace/ | grep warp
{ config, lib, pkgs, ... }:

let
  netns      = "warp";
  netnsPath  = "/run/netns/${netns}";
  hostVeth   = "veth-warp-h";
  nsVeth     = "veth-warp";
  hostIp     = "10.99.1.1";
  nsIp       = "10.99.1.2";
  subnet     = "10.99.1.0/30";
  wanIface   = "wan0";
in
{
  # ── Cloudflare WARP service ────────────────────────────────────────
  services.cloudflare-warp = {
    enable = true;
  };

  nixpkgs.config.allowUnfree = true;  # cloudflare-warp is unfree

  # ── warp-cli wrapper: transparently runs inside warpns ──────────────
  # The real warp-cli binary still works from any netns (it talks to the
  # daemon over a unix socket which is in the mount-ns, not netns). But
  # interface-introspection commands (status, connect verification) need
  # to see CloudflareWARP, which only exists in warpns. This wrapper
  # shadows the upstream warp-cli in PATH and re-execs inside warpns so
  # an admin can just `sudo warp-cli status` without thinking about it.
  # Requires CAP_SYS_ADMIN (sudo or already-root) because `ip netns exec`
  # is privileged. The systemd services already run as root and use
  # NetworkNamespacePath, so they don't need this wrapper.
  environment.systemPackages = [
    (pkgs.writeShellScriptBin "warp-cli" ''
      if [ "$(id -u)" -ne 0 ]; then
        echo "warp-cli wrapper: needs root (uses 'ip netns exec warp')" >&2
        echo "Try: sudo warp-cli $*" >&2
        exit 1
      fi
      exec ${pkgs.iproute2}/bin/ip netns exec warp \
        ${pkgs.cloudflare-warp}/bin/warp-cli "$@"
    '')
  ];

  # ── Create the warp netns and its veth bridge to main ──────────────
  # Runs before cloudflare-warp.service so the netns exists when the
  # daemon launches into it. Idempotent — tears down and recreates state
  # on every start (safe because the netns is owned solely by us).
  systemd.services.setup-warp-netns = {
    description = "Create warp network namespace + veth + NAT";
    after    = [ "network-online.target" "nftables.service" "wireguard-wg-mullvad.service" ];
    requires = [ "network-online.target" "nftables.service" ];
    before   = [ "cloudflare-warp.service" ];
    wantedBy = [ "cloudflare-warp.service" "multi-user.target" ];
    # Re-trigger if nftables ruleset reloads (which drops inline rules).
    partOf   = [ "nftables.service" ];

    path = with pkgs; [ iproute2 nftables coreutils gawk procps ];

    serviceConfig = {
      Type           = "oneshot";
      RemainAfterExit = true;
    };

    script = ''
      set -e

      # Idempotent cleanup
      ip link del ${hostVeth} 2>/dev/null || true
      ip netns del ${netns} 2>/dev/null || true
      nft list table inet warp-netns >/dev/null 2>&1 && nft delete table inet warp-netns || true

      # Create the netns and its DNS config
      ip netns add ${netns}
      mkdir -p /etc/netns/${netns}
      printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' \
        > /etc/netns/${netns}/resolv.conf

      # veth pair: host (main) ↔ warpns
      ip link add ${hostVeth} type veth peer name ${nsVeth} netns ${netns}
      ip addr add ${hostIp}/30 dev ${hostVeth}
      ip link set ${hostVeth} up
      ip -n ${netns} addr add ${nsIp}/30 dev ${nsVeth}
      ip -n ${netns} link set ${nsVeth} up
      ip -n ${netns} link set lo up
      ip -n ${netns} route add default via ${hostIp}

      # ip_forward sysctl is per-netns and defaults to 0 in a fresh netns.
      # Without this, packets entering warpns on veth-warp can't be
      # forwarded onward to CloudflareWARP.
      ip netns exec ${netns} sysctl -w net.ipv4.ip_forward=1 >/dev/null

      # NAT outbound from warpns. Two oifname rules cover the case
      # where main's routing chain sends our packets via wan0 directly
      # (uncommon, requires fwmark 0xca6c) OR via Mullvad (the typical
      # path, since main's default ip rule "not fwmark 0xca6c → mullvad"
      # catches unmarked warpns traffic and routes it via wg-mullvad).
      # Also masquerades LAN-originated traffic forwarded INTO warpns so
      # the warpns side sees a 10.99.1.1 source it can route back to.
      # MSS clamp on the veth path because WARP's tunnel MTU (~1280) is
      # smaller than LAN MTU (1500) — without clamping, HTTPS handshakes
      # blackhole on PMTU-blocked paths.
      nft -f - <<EOF
      table inet warp-netns {
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          ip saddr ${subnet} oifname "${wanIface}" masquerade
          ip saddr ${subnet} oifname "wg-mullvad" masquerade
          oifname "${hostVeth}" masquerade
        }

        chain forward-mss-clamp {
          type filter hook forward priority mangle + 1; policy accept;
          oifname "${hostVeth}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
          iifname "${hostVeth}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
        }
      }
      EOF

      # Allow warpns→{wan0,wg-mullvad} forwarding in the main filter chain.
      # Without these, the default DROP policy catches the bootstrap traffic.
      nft insert rule inet filter forward iifname "${hostVeth}" oifname "${wanIface}" accept
      nft insert rule inet filter forward iifname "${wanIface}" oifname "${hostVeth}" ct state established,related accept
      nft insert rule inet filter forward iifname "${hostVeth}" oifname "wg-mullvad" accept
      nft insert rule inet filter forward iifname "wg-mullvad" oifname "${hostVeth}" ct state established,related accept

      # Allow LAN → warpns forwarding (for the LAN-web-via-WARP path) and
      # the reply path back to LAN clients.
      nft insert rule inet filter forward iifname "br-lan" oifname "${hostVeth}" accept
      nft insert rule inet filter forward iifname "${hostVeth}" oifname "br-lan" ct state established,related accept

      # ── LAN web (fwmark 0xc100, set in modules/firewall.nix mangle) ──
      # routes via a dedicated custom table 60 whose default is the warpns
      # veth peer. Packets enter warpns, where WARP's own ip-rule captures
      # them and tunnels via CloudflareWARP to Cloudflare.
      ip route flush table 60 2>/dev/null || true
      ip route add default via ${nsIp} dev ${hostVeth} table 60
      ip rule del fwmark 0xc100 lookup 60 priority 6 2>/dev/null || true
      ip rule add fwmark 0xc100 lookup 60 priority 6

      # ── Inside-warpns rules: NAT + MSS clamp on CloudflareWARP egress ─
      #
      # NAT (postrouting/nat): WARP daemon's own traffic naturally gets
      # source = CloudflareWARP's /32 IP. But forwarded LAN packets arrive
      # in warpns with source = 10.99.1.1 (the host veth IP, set by main
      # netns's masquerade). Cloudflare's MASQUE server can't route a
      # private 10.x source back, so replies vanish. Masquerade at the
      # CloudflareWARP egress rewrites source → the WARP-assigned IP, and
      # conntrack reverses on the reply path back to the LAN client.
      #
      # MSS clamp (postrouting/mangle): CloudflareWARP MTU is 1280. A
      # plain rt-mtu clamp on the veth path sees the veth's 1500 MTU, not
      # the tunnel's 1280 — useless. Clamping on oifname CloudflareWARP
      # uses a fixed MSS sized for the smaller of v4/v6 paths:
      #   1280 (tunnel MTU) − 40 (IPv6 hdr) − 20 (TCP hdr) = 1220.
      # IPv4 traffic is 20 bytes under-budget but it costs nothing; the
      # `inet` family rule applies to both v4 and v6 forwarded TCP SYNs.
      ip netns exec ${netns} nft -f - <<EOF
      table inet warp-forward-nat {
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          oifname "CloudflareWARP" masquerade
        }
        chain mss-clamp {
          type filter hook postrouting priority mangle; policy accept;
          oifname "CloudflareWARP" tcp flags syn / syn,rst tcp option maxseg size set 1220
        }
      }
      EOF
    '';

    preStop = ''
      ip rule del fwmark 0xc100 lookup 60 priority 6 2>/dev/null || true
      ip route flush table 60 2>/dev/null || true
      # Inside-warpns NAT table — deleted automatically when netns goes away,
      # but explicit cleanup helps if the netns is being kept across restarts.
      ip netns exec ${netns} nft list table inet warp-forward-nat >/dev/null 2>&1 \
        && ip netns exec ${netns} nft delete table inet warp-forward-nat || true
      ip link del ${hostVeth} 2>/dev/null || true
      ip netns del ${netns} 2>/dev/null || true
      nft list table inet warp-netns >/dev/null 2>&1 && nft delete table inet warp-netns || true
    '';
  };

  # Path-watcher: nixos-rebuild *reloads* nftables (doesn't restart it),
  # which silently drops the inline filter-forward rules we inserted above.
  # `partOf nftables` only catches restart/stop. Trigger on /etc/nftables.conf
  # symlink target changes to re-inject after any rebuild.
  systemd.paths.setup-warp-netns-watcher = {
    description = "Re-run setup-warp-netns when nftables ruleset changes";
    wantedBy = [ "multi-user.target" ];
    pathConfig = {
      PathChanged = "/etc/nftables.conf";
      Unit = "setup-warp-netns.service";
    };
  };

  # ── Move all WARP services into warpns ─────────────────────────────
  # NetworkNamespacePath puts the service inside the named netns at exec
  # time. The daemon's ip-rule manipulations, CloudflareWARP interface
  # creation, and kill-switch nft tables are confined to warpns.
  # The helper services (warp-cli wrappers) are also in warpns so they
  # share the daemon's view of the world.
  systemd.services.cloudflare-warp = {
    after    = [ "setup-warp-netns.service" ];
    requires = [ "setup-warp-netns.service" ];
    serviceConfig.NetworkNamespacePath = lib.mkForce netnsPath;
  };

  # ── Split tunnel: exclude IPs that must bypass WARP ─────────────────
  # Mullvad endpoint must bypass WARP so WireGuard packets reach the
  # server directly. DNS upstreams (Quad9) must bypass WARP so that a
  # WARP outage doesn't kill DNS — without DNS, WARP can't recover
  # (circular dependency). Excluded IPs route through Mullvad instead.
  systemd.services.warp-split-tunnel = {
    description = "Exclude Mullvad + DNS IPs from WARP split tunnel";
    after = [ "cloudflare-warp.service" ];
    wants = [ "cloudflare-warp.service" ];
    wantedBy = [ "multi-user.target" ];

    path = with pkgs; [ cloudflare-warp ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      # Same netns as the daemon so warp-cli's local socket lookup works.
      NetworkNamespacePath = netnsPath;
    };

    script = ''
      for i in $(seq 1 30); do
        if warp-cli status &>/dev/null; then
          break
        fi
        sleep 1
      done
      # Mullvad endpoint — so WireGuard packets reach the server
      warp-cli tunnel ip add ${config.firewall.mullvad.endpoint} || true
      # Quad9 DNS upstreams — so DNS works even when WARP is down
      warp-cli tunnel ip add 9.9.9.11 || true
      warp-cli tunnel ip add 149.112.112.11 || true
      echo "Split tunnel exclusions applied"
    '';
  };

  # ── Remove WARP's redundant nftables kill switch ────────────────────
  # WARP installs `table inet cloudflare-warp` with policy drop on input
  # and output. Inside warpns this is harmless (warpns is isolated), but
  # warp-svc reloads it on connectivity changes which can interfere with
  # our own NAT rules in warpns. Watch and delete reflexively.
  systemd.services.warp-lan-access = {
    description = "Remove WARP redundant nftables kill switch";
    after = [ "cloudflare-warp.service" ];
    wants = [ "cloudflare-warp.service" ];
    wantedBy = [ "multi-user.target" ];

    path = [ pkgs.nftables pkgs.coreutils ];

    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = 2;
      NetworkNamespacePath = netnsPath;
    };

    script = ''
      nft delete table inet cloudflare-warp 2>/dev/null || true

      nft monitor | while read -r line; do
        case "$line" in
          *cloudflare-warp*)
            sleep 1
            nft delete table inet cloudflare-warp 2>/dev/null || true
            ;;
        esac
      done
    '';
  };

  # ── Wait for CloudflareWARP interface (inside warpns) ──────────────
  systemd.services.warp-wait = {
    description = "Wait for CloudflareWARP tunnel interface";
    after = [ "cloudflare-warp.service" ];
    wants = [ "cloudflare-warp.service" ];
    wantedBy = [ "multi-user.target" ];

    path = [ pkgs.iproute2 pkgs.coreutils ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      NetworkNamespacePath = netnsPath;
    };

    script = ''
      for i in $(seq 1 30); do
        if ip link show CloudflareWARP &>/dev/null; then
          echo "CloudflareWARP interface is up"
          exit 0
        fi
        echo "Waiting for CloudflareWARP interface... ($i/30)"
        sleep 2
      done
      echo "WARNING: CloudflareWARP interface not found after 60s"
      echo "Run setup-warp.sh if this is a fresh install"
    '';
  };
}
