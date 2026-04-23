# Minimal CachyOS LTS kernel optimized for an N5105 headless firewall appliance.
#
# Uses CachyOS LTS kernel (BORE scheduler, performance patches, long-term
# support) with unnecessary subsystems stripped out. Prioritizes stability
# for a 24/7 perimeter device. N5105 Jasper Lake = Tremont cores (x86-64-v2).
{ config, lib, pkgs, ... }:

{
  # ── CachyOS LTS kernel — stability + BORE scheduler ──────────────
  boot.kernelPackages = pkgs.linuxPackages_cachyos-lts;

  # ── Strip unused subsystems & tune for firewall workload ──────────
  boot.kernelPatches = [{
    name = "firewall-minimal";
    patch = null;
    structuredExtraConfig = with lib.kernel; {
      # ── Disable: sound ──────────────────────────────────────────
      SOUND = no;

      # ── Disable: GPU / display ──────────────────────────────────
      DRM = no;
      FB = lib.mkForce no;
      VGA_CONSOLE = lib.mkForce no;

      # ── Disable: wireless / bluetooth ───────────────────────────
      WIRELESS = lib.mkForce no;
      CFG80211 = lib.mkForce no;
      MAC80211 = lib.mkForce no;
      BLUETOOTH = lib.mkForce no;

      # ── Disable: input devices we don't need ────────────────────
      INPUT_TOUCHSCREEN = no;
      INPUT_TABLET = no;
      INPUT_JOYSTICK = no;

      # ── Disable: media / cameras ────────────────────────────────
      MEDIA_SUPPORT = no;

      # ── Disable: legacy / unused networking ─────────────────────
      INFINIBAND = no;
      ISDN = no;
      ATM = no;
      HAMRADIO = no;
      CAN = no;
      NFC = no;
      WIMAX = no;
      PCMCIA = no;
      WWAN = no;

      # ── Disable: staging drivers ────────────────────────────────
      STAGING = no;

      # ── Disable: unused filesystems ─────────────────────────────
      # Keep: ext4, vfat (EFI), tmpfs, proc, sysfs, nfs (optional)
      XFS_FS = no;
      BTRFS_FS = no;
      REISERFS_FS = no;
      JFS_FS = no;
      GFS2_FS = no;
      OCFS2_FS = no;
      NILFS2_FS = no;
      F2FS_FS = no;
      NTFS_FS = no;
      NTFS3_FS = no;
      HFS_FS = no;
      HFSPLUS_FS = no;
      UFS_FS = no;
      EROFS_FS = no;
      BCACHEFS_FS = lib.mkForce no;

      # ── Disable: virtualization guests (this IS the host) ───────
      HYPERV = no;
      XEN = lib.mkForce no;
      VMWARE_VMCI = no;
      VBOXGUEST = no;

      # ── Enable: networking performance ──────────────────────────
      # Netfilter / nftables (should already be on, be explicit)
      NF_TABLES = yes;
      NF_CONNTRACK = yes;
      NETFILTER_XT_MATCH_CONNTRACK = yes;
      IP_NF_NAT = yes;

      # TUN/TAP for WARP, veth for namespaces/containers
      TUN = yes;
      VETH = yes;

      # TCP congestion control
      TCP_CONG_BBR = yes;
      DEFAULT_BBR = yes;

      # Busy polling for lower latency packet processing
      NET_RX_BUSY_POLL = yes;

      # ── Enable: Intel i226 NIC driver ───────────────────────────
      IGC = yes;  # Built-in, not module — faster boot

      # ── Preemption: voluntary (good balance for router) ─────────
      PREEMPT_VOLUNTARY = lib.mkForce yes;
      PREEMPT = lib.mkForce no;
      PREEMPT_NONE = lib.mkForce no;
    };
  }];

  # ── TCP BBR as default congestion control ─────────────────────────
  boot.kernelModules = [ "tcp_bbr" ];
  boot.kernel.sysctl = {
    "net.ipv4.tcp_congestion_control" = "bbr";
    "net.core.default_qdisc" = "fq";
  };
}
