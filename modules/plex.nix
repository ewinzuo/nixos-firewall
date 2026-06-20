# Plex Media Server with Intel Quick Sync hardware transcoding.
#
# Designed for headless Topton N5105 (Jasper Lake) — uses the iGPU
# for zero-copy transcode via VA-API. Accessible from LAN only.
#
# After first deploy:
#   1. Open http://192.168.1.1:32400/web from a LAN client
#   2. Sign in with your Plex account to claim the server
#   3. Add media libraries pointing to /srv/media/*
#
# Media directory layout (create these on the server):
#   /srv/media/movies/
#   /srv/media/tv/
#   /srv/media/music/
{ config, lib, pkgs, ... }:

let
  cfg = config.services.plex;
in
{
  # ── Plex Media Server ──────────────────────────────────────────────
  services.plex = {
    enable = true;
    openFirewall = false;  # We manage firewall rules ourselves
  };

  # ── Intel Quick Sync (VA-API) for hardware transcoding ─────────────
  # N5105 Jasper Lake uses the i915 kernel driver. The iHD media driver
  # provides VA-API for Plex's hardware transcoder.
  hardware.graphics = {
    enable = true;
    extraPackages = with pkgs; [
      intel-media-driver    # iHD VA-API driver (Broadwell+)
      intel-compute-runtime # OpenCL for HDR tone mapping
    ];
  };

  # Ensure the plex user can access the GPU render device
  users.users.plex.extraGroups = [ "render" "video" ];

  # ── Media storage ──────────────────────────────────────────────────
  # Create the media directory structure. Add your media here or mount
  # external storage at /srv/media.
  systemd.tmpfiles.rules = [
    "d /srv/media 0775 plex plex - -"
    "d /srv/media/movies 0775 plex plex - -"
    "d /srv/media/tv 0775 plex plex - -"
    "d /srv/media/music 0775 plex plex - -"
  ];

  # ── Firewall: allow Plex from LAN only ─────────────────────────────
  # Plex uses:
  #   32400/tcp  — web UI + streaming
  #   1900/udp   — DLNA discovery (optional)
  #   32469/tcp  — DLNA server (optional)
  #   8324/tcp   — Roku companion (optional)
  #   32410-32414/udp — GDM network discovery
  networking.nftables.ruleset = lib.mkAfter ''
    table inet plex {
      chain input {
        type filter hook input priority filter + 5; policy accept;
        iifname "br-lan" tcp dport 32400 accept
        iifname "br-lan" udp dport { 1900, 32410-32414 } accept
        iifname "br-lan" tcp dport { 8324, 32469 } accept
      }
    }
  '';

  # ── Performance: let Plex use enough file descriptors ──────────────
  systemd.services.plex.serviceConfig = {
    LimitNOFILE = 65536;
  };

  # Allow unfree (Plex is proprietary)
  nixpkgs.config.allowUnfree = true;
}
