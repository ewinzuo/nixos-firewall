# Hardware configuration for Intel N5105 (Jasper Lake) firewall appliance.
# 4C/4T @ 2.0–2.9GHz, 8GB DDR4, Intel i226-V NICs (igc driver).
# Generate the real version on your hardware with: nixos-generate-config
# This is a representative template — adjust disk/NIC PCI paths after generation.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];

  boot.initrd.availableKernelModules = [
    "ahci" "xhci_pci" "usb_storage" "sd_mod" "sdhci_pci"
    # Intel i226-V (common on N5105 boards)
    "igc"
  ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  # Placeholder — replace with your actual disk layout
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };

  fileSystems."/boot" = {
    device = "/dev/disk/by-label/boot";
    fsType = "vfat";
    options = [ "fmask=0077" "dmask=0077" ];
  };

  swapDevices = [ ];

  hardware.cpu.intel.updateMicrocode =
    lib.mkDefault config.hardware.enableRedistributableFirmware;

  # ── N5105 / Jasper Lake optimizations ──────────────────────────────
  # Intel i226-V NIC performance defaults
  boot.kernelParams = [
    # Headless — skip GPU initialization
    "nomodeset"
    # Hardware watchdog for hang recovery (Intel TCO on N5105)
    "iTCO_wdt.nowayout=1"
  ];

  # Distribute NIC interrupts across all 4 cores
  services.irqbalance.enable = true;

  powerManagement = {
    # Disable CPU frequency scaling — keep cores at max for consistent latency
    cpuFreqGovernor = "performance";
  };
}
