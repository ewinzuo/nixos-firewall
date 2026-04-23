# Kernel tuning for a headless firewall appliance.
#
# Uses the default NixOS LTS kernel with networking performance tweaks.
# Prioritizes stability for a 24/7 perimeter device.
{ config, lib, pkgs, ... }:

{
  # ── TCP BBR as default congestion control ─────────────────────────
  boot.kernelModules = [ "tcp_bbr" ];
  boot.kernel.sysctl = {
    "net.ipv4.tcp_congestion_control" = "bbr";
    "net.core.default_qdisc" = "fq";
  };
}
