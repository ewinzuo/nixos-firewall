{
  description = "NixOS firewall/router appliance with Cloudflare WARP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, sops-nix, ... }:
  let
    # Standalone build uses the template hardware-configuration.nix and
    # picks up secrets-config.nix if it exists on disk (for on-box rebuilds).
    secretsModule =
      if builtins.pathExists ./secrets-config.nix then ./secrets-config.nix
      else { };
  in
  {
    # ── Reusable NixOS modules ─────────────────────────────────────────
    # Import in your own flake:
    #   nixos-firewall.nixosModules.default  (includes sops secret wiring)
    #   sops-nix.nixosModules.sops           (you provide this input)
    # Then set firewall.* options and sops.defaultSopsFile in your config.
    nixosModules.default = {
      imports = [
        ./configuration.nix
        ./modules/options.nix
        ./modules/kernel.nix
        ./modules/network.nix
        ./modules/firewall.nix
        ./modules/dhcp-dns.nix
        ./modules/warp.nix
        ./modules/mullvad.nix
        ./modules/sops.nix
      ];
    };

    nixosModules.plex = ./modules/plex.nix;

    # ── Standalone build (on-box or ISO install) ───────────────────────
    nixosConfigurations.firewall = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        self.nixosModules.default
        sops-nix.nixosModules.sops
        ./hardware-configuration.nix
        { sops.defaultSopsFile = ./secrets/mullvad.yaml; }
        secretsModule
      ];
    };

    nixosConfigurations."firewall-iso" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        self.nixosModules.default
        sops-nix.nixosModules.sops
        ./hardware-configuration.nix
        { sops.defaultSopsFile = ./secrets/mullvad.yaml; }
        secretsModule
      ] ++ [
        ({ modulesPath, pkgs, lib, ... }: {
          imports = [ (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix") ];

          # squashfs permissions cause StrictModes to reject authorized_keys
          services.openssh.settings.StrictModes = lib.mkForce false;

          environment.systemPackages = with pkgs; [
            nixos-install-tools
            parted
            dosfstools
            e2fsprogs
          ];

          # ── Setup wizard — run from the ISO to configure the appliance ──
          environment.etc."setup-wizard.sh" = {
            mode = "0755";
            source = ./scripts/setup-wizard.sh;
          };

          # ── WARP setup — run manually after first boot (requires TOS acceptance) ──
          environment.etc."setup-warp.sh" = {
            mode = "0755";
            source = ./setup-warp.sh;
          };

          # ── Install script — partitions, installs, places secrets ──
          environment.etc."install.sh" = {
            mode = "0755";
            text = ''
              #!/bin/sh
              set -e

              CONFIG_DIR="/etc/nixos-config"
              SECRETS="$CONFIG_DIR/secrets-config.nix"

              if [ ! -f "$SECRETS" ]; then
                echo "ERROR: secrets-config.nix not found."
                echo "Run /etc/setup-wizard.sh first to configure the appliance."
                exit 1
              fi

              echo "Installing firewall..."
              echo "Building system from flake (this may take a few minutes)..."
              nixos-install \
                --flake "$CONFIG_DIR#firewall" \
                --no-channel-copy \
                --option substituters ""

              # Copy full config (including secrets-config.nix) to installed system
              mkdir -p /mnt/etc/nixos
              cp -r "$CONFIG_DIR"/. /mnt/etc/nixos/

              # Copy WARP setup script for post-boot use
              cp /etc/setup-warp.sh /mnt/etc/setup-warp.sh 2>/dev/null || true

              echo ""
              echo "=== Installation complete ==="
              echo ""
              echo "After reboot, set up production secrets (one-time):"
              echo "  1. Get the firewall's age pubkey:"
              echo "     ssh root@<firewall-ip> 'cat /etc/ssh/ssh_host_ed25519_key.pub' | ssh-to-age"
              echo "  2. Add that pubkey to .sops.yaml under &firewall_prod"
              echo "  3. Encrypt the Mullvad private key:"
              echo "     sops secrets/mullvad.yaml"
              echo "  4. Deploy: nixos-rebuild switch --flake .#firewall --target-host root@<firewall-ip>"
              echo ""
              echo "Then run WARP setup:"
              echo "  ssh root@<firewall-ip> /etc/setup-warp.sh"
              echo ""
              echo "Run: reboot"
            '';
          };

          environment.etc."nixos-config" = {
            source = ./.;
          };

          # Pre-cache the system closure for offline install
          isoImage.storeContents = [ self.nixosConfigurations.firewall.config.system.build.toplevel ];
        })
      ];
    };

    packages.x86_64-linux.firewall-iso =
      self.nixosConfigurations."firewall-iso".config.system.build.isoImage;

    # Sandboxed VM test — validates firewall, DHCP, DNS, kill switch.
    # Run: nix build .#checks.x86_64-linux.firewall-test -L
    checks.x86_64-linux.firewall-test = import ./tests/firewall-test.nix {
      inherit nixpkgs;
    };

    # WARP test VM with real internet access.
    # Build: nix build .#warp-test-vm
    # Run:   ./result/bin/run-warp-test-vm
    # Then inside the VM: /etc/setup-warp.sh && /etc/test-warp-live.sh
    nixosConfigurations."warp-test-vm" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./tests/warp-vm.nix
        (nixpkgs + "/nixos/modules/virtualisation/qemu-vm.nix")
      ];
    };

    packages.x86_64-linux.warp-test-vm =
      self.nixosConfigurations."warp-test-vm".config.system.build.vm;

    # ── Black-box e2e double-tunnel test ─────────────────────────────
    # Three live-internet VMs (firewall + client + upstream) wired with
    # QEMU socket vlans. The runner script tests/e2e/run-e2e.sh launches
    # them, drives assertions over SSH, and proves wan0 only ever emits
    # WireGuard. Requires sops-decrypted Mullvad creds (see .sops.yaml).
    #
    # Build:  nix build .#e2e-firewall-vm  (+ .#e2e-client-vm, .#e2e-upstream-vm)
    # Run:    ./tests/e2e/run-e2e.sh
    nixosConfigurations."e2e-firewall-vm" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./tests/e2e/firewall-vm.nix
        (nixpkgs + "/nixos/modules/virtualisation/qemu-vm.nix")
      ];
    };
    nixosConfigurations."e2e-client-vm" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./tests/e2e/client-vm.nix
        (nixpkgs + "/nixos/modules/virtualisation/qemu-vm.nix")
      ];
    };
    nixosConfigurations."e2e-upstream-vm" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./tests/e2e/upstream-vm.nix
        (nixpkgs + "/nixos/modules/virtualisation/qemu-vm.nix")
      ];
    };

    packages.x86_64-linux.e2e-firewall-vm =
      self.nixosConfigurations."e2e-firewall-vm".config.system.build.vm;
    packages.x86_64-linux.e2e-client-vm =
      self.nixosConfigurations."e2e-client-vm".config.system.build.vm;
    packages.x86_64-linux.e2e-upstream-vm =
      self.nixosConfigurations."e2e-upstream-vm".config.system.build.vm;

    apps.x86_64-linux.e2e-test =
      let pkgs = import nixpkgs { system = "x86_64-linux"; };
      in {
        type = "app";
        program = toString (pkgs.writeShellScript "run-e2e-test" ''
          exec ${toString ./tests/e2e/run-e2e.sh} "$@"
        '');
      };
  };
}
