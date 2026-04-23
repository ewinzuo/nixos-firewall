# Hardware configuration template for x86_64 firewall appliances.
# Generate the real version on your hardware with: nixos-generate-config
# This is a starting point — adjust disk layout and NIC drivers for your box.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];

  boot.initrd.availableKernelModules = [
    "ahci" "xhci_pci" "usb_storage" "sd_mod" "sdhci_pci"
    # Common NIC drivers — the kernel loads the right one automatically.
    # Add yours here if it's not built-in (run `lspci -k` to check).
    "igc"       # Intel i226-V (common on N5105/N100 boards)
    "igb"       # Intel i210/i211/i350
    "ixgbe"     # Intel 10GbE (X520, X540, X550)
    "e1000e"    # Intel desktop/laptop GbE
    "r8169"     # Realtek GbE
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

  # Microcode — enable both, only the matching one loads
  hardware.cpu.intel.updateMicrocode =
    lib.mkDefault config.hardware.enableRedistributableFirmware;
  hardware.cpu.amd.updateMicrocode =
    lib.mkDefault config.hardware.enableRedistributableFirmware;

  boot.kernelParams = [
    # Headless — skip GPU initialization
    "nomodeset"
  ];

  # Distribute NIC interrupts across all cores
  services.irqbalance.enable = true;

  powerManagement = {
    # Disable CPU frequency scaling — keep cores at max for consistent latency
    cpuFreqGovernor = "performance";
  };
}
