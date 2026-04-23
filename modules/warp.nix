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
# Split tunnel: warp-svc excludes RFC1918 by default. To exclude additional
# IPs from WARP (e.g., gaming servers), use:
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

  # ── Allow LAN through WARP's nftables kill switch ───────────────────
  # WARP installs `table inet cloudflare-warp` with policy drop on input
  # and output, blocking LAN services (SSH, DNS, DHCP, ping) when WARP is
  # disconnected.  We inject br-lan accept rules so local management always
  # works.  WARP reloads its firewall on connectivity changes, so we use
  # `nft monitor` to re-inject immediately.
  # Note: Mullvad endpoint traffic is handled by WARP's split tunnel
  # exclude list (see mullvad.nix), not by nftables injection.
  systemd.services.warp-lan-access = {
    description = "Allow LAN through WARP nftables kill switch";
    after = [ "cloudflare-warp.service" ];
    wants = [ "cloudflare-warp.service" ];
    wantedBy = [ "multi-user.target" ];

    path = [ pkgs.nftables pkgs.gnugrep pkgs.coreutils ];

    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = 2;
    };

    script = ''
      inject() {
        if nft list table inet cloudflare-warp &>/dev/null; then
          if ! nft list chain inet cloudflare-warp input 2>/dev/null | grep -q 'comment "nixos-override"'; then
            nft insert rule inet cloudflare-warp input iifname "br-lan" accept comment \"nixos-override\"
            nft insert rule inet cloudflare-warp output oifname "br-lan" accept comment \"nixos-override\"
            echo "Injected LAN accept rules into cloudflare-warp table"
          fi
        fi
      }

      # Inject on startup
      inject

      # Re-inject whenever WARP reloads its rules
      nft monitor | while read -r line; do
        case "$line" in
          *cloudflare-warp*) inject ;;
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
