# Cloudflare WARP via warp-svc (official client) + MASQUE protocol.
#
# How it works:
#   1. warp-svc runs as a systemd service and creates the "CloudflareWARP" interface
#   2. We use "tunnel_only" mode so warp-svc doesn't hijack DNS
#   3. warp-svc manages its own routing (table 65743) — we don't fight it
#   4. All internet traffic goes through WARP/MASQUE by default
#   5. LAN traffic (10.0.0.0/8, etc.) is excluded from the tunnel automatically
#   6. nftables kill switch on wan0 blocks web traffic as defense-in-depth
#
# Split tunnel: warp-svc excludes RFC1918 by default. Additional IPs
# (Mullvad endpoint, DNS upstreams) are excluded by warp-split-tunnel.service
# so they route through Mullvad instead. To exclude more IPs manually:
#   warp-cli tunnel ip add <CIDR>
#
# Setup (run once on the deployed box):
#   sudo ./setup-warp.sh
#   — or manually:
#   1. sudo warp-cli registration delete 2>/dev/null; sudo warp-cli --accept-tos registration new
#   2. sudo warp-cli mode tunnel_only
#   3. sudo warp-cli tunnel protocol set MASQUE
#   4. sudo warp-cli connect
#   5. Verify: curl -s https://www.cloudflare.com/cdn-cgi/trace/ | grep warp
{ config, lib, pkgs, ... }:

{
  # ── Cloudflare WARP service ────────────────────────────────────────
  services.cloudflare-warp = {
    enable = true;
  };

  nixpkgs.config.allowUnfree = true;  # cloudflare-warp is unfree

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
  # and output.  This is redundant — our nftables in firewall.nix already
  # block br-lan→wan0 forwarding and restrict wan0 output to WireGuard+DHCP.
  # Worse, WARP reloads this table on connectivity changes (WAN carrier
  # drop, tunnel reconnect), which locks out LAN management (SSH, DNS,
  # DHCP).  Injecting rules into WARP's table doesn't survive these
  # reloads reliably.  Instead, delete the table entirely and let our
  # own kill switch handle it.
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

  # ── Wait for CloudflareWARP interface before network is "online" ───
  systemd.services.warp-wait = {
    description = "Wait for CloudflareWARP tunnel interface";
    after = [ "cloudflare-warp.service" ];
    wants = [ "cloudflare-warp.service" ];
    wantedBy = [ "multi-user.target" ];

    path = [ pkgs.iproute2 pkgs.coreutils ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
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
