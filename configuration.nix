{ config, pkgs, lib, ... }:

let
  user = config.firewall.user;
in
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  nix.settings.trusted-users = [ user.name ];
  nix.settings.require-sigs = false;

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # Kernel: CachyOS + minimal config in modules/kernel.nix
  # Kernel hardening sysctls are in modules/firewall.nix

  networking.hostName = user.hostName;

  time.timeZone = "America/Los_Angeles";
  i18n.defaultLocale = "en_US.UTF-8";

  # Headless appliance — no GUI
  # Disable systemd SSH proxy — not needed on a firewall, and its client config
  # causes sshd to fail with "bad configuration option: Host" on NixOS + systemd 256+.
  programs.ssh.systemd-ssh-proxy.enable = false;

  # sshd listens on 192.168.1.1 (br-lan) — wait for it to be assigned first.
  # nixpkgs bug #105570: sshd starts before listenAddress IP is available.
  systemd.services.sshd.after = [ "network-online.target" ];
  systemd.services.sshd.wants = [ "network-online.target" ];

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
    };
    # Only listen on LAN
    listenAddresses = [
      { addr = "192.168.1.1"; port = 22; }
    ];
  };

  users.users.${user.name} = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = user.sshKeys;
  };

  # Require password for sudo on a perimeter device
  security.sudo.wheelNeedsPassword = true;

  environment.systemPackages = with pkgs; [
    vim-full
    wget
    htop
    tcpdump
    nftables
    conntrack-tools
    ethtool
    iperf3
    cloudflare-warp
    dnsutils
    mtr
    tmux
  ];

  nixpkgs.config.allowUnfree = true;

  # ── Stability: auto-recover from failures ──────────────────────────
  # Reboot on kernel panic after 10 seconds
  boot.kernel.sysctl."kernel.panic" = 10;
  boot.kernel.sysctl."kernel.panic_on_oops" = 1;

  # Hardware watchdog — reboot if system hangs
  systemd.settings.Manager.RuntimeWatchdogSec = "30s";
  systemd.settings.Manager.RebootWatchdogSec = "60s";

  # ── Stability: prevent disk fill ───────────────────────────────────
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 30d";
  };

  # Keep only the last 5 system generations
  boot.loader.systemd-boot.configurationLimit = 5;

  # ── Stability: journal size limits ─────────────────────────────────
  services.journald.extraConfig = ''
    SystemMaxUse=500M
    MaxRetentionSec=1month
  '';

  system.stateVersion = "25.05";
}
