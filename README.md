# nixos-firewall

NixOS-based firewall/router appliance with a double-VPN privacy stack.

```
LAN clients → br-lan → CloudflareWARP (MASQUE) → wg-mullvad (WireGuard) → wan0 → Internet
```

- **Destinations** see a Cloudflare/WARP IP
- **Cloudflare** sees a Mullvad exit IP (not your real IP)
- **Your ISP** sees WireGuard to Mullvad (not Cloudflare)
- **Kill switch** drops all unencrypted WAN traffic — if both tunnels fail, nothing leaks

## Features

- **nftables firewall** — default-deny WAN, stateful tracking, bogon filtering, ICMP rate limiting
- **Cloudflare WARP** (MASQUE) — web traffic tunneled through Cloudflare
- **Mullvad WireGuard** — underlay for WARP with fwmark routing (survives WAN carrier drops)
- **Kill switch** — bare WAN traffic is dropped; only VPN-protected traffic leaves the box
- **Self-healing** — fwmark routing eliminates endpoint route dependency; tunnels recover automatically after ISP outages
- **Kea DHCP + Unbound DNS** — LAN clients get addresses and recursive DNS-over-TLS via Quad9
- **DNS forcing** — all LAN DNS is redirected to Unbound regardless of client settings
- **3-port LAN bridge** — ports 2-4 bridged as `br-lan`
- **Setup wizard** — interactive ISO script configures NICs, Mullvad, SSH keys
- **Integration tests** — NixOS VM test + 3-VM black-box e2e suite (30 assertions)

## Hardware requirements

- x86_64 machine with 2+ ethernet ports (4 recommended)
- 4GB+ RAM
- Tested with Intel i226-V (igc); also supports i210/i350, 10GbE, Realtek GbE

## Usage

### As a NixOS module (recommended)

Import the firewall into your own flake and provide machine-specific config:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    nixos-firewall.url = "github:ewinzuo/nixos-firewall";
    nixos-firewall.inputs.nixpkgs.follows = "nixpkgs";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, nixos-firewall, sops-nix, ... }: {
    nixosConfigurations.my-firewall = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixos-firewall.nixosModules.default
        sops-nix.nixosModules.sops
        ./hardware-configuration.nix
        ./secrets-config.nix
        { sops.defaultSopsFile = ./secrets/mullvad.yaml; }
      ];
    };
  };
}
```

Then deploy:

```sh
nixos-rebuild switch --flake .#my-firewall --target-host user@firewall-ip --sudo
```

### Standalone (ISO install)

Build the ISO, flash it, and run the setup wizard:

```sh
nix build .#firewall-iso
# Flash result/iso/*.iso to USB, boot target machine
/etc/setup-wizard.sh   # configure NICs, Mullvad, SSH keys
/etc/install.sh        # partition + install
# Reboot, then:
sudo /etc/setup-warp.sh
```

## Configuration

All machine-specific values are set via `firewall.*` options. See `secrets-config.nix.example`:

```nix
{
  firewall.user = {
    name     = "admin";
    hostName = "my-firewall";
    sshKeys  = [ "ssh-ed25519 AAAA..." ];
  };

  firewall.network = {
    wan0Mac = "aa:bb:cc:dd:ee:01";
    lan1Mac = "aa:bb:cc:dd:ee:02";
    lan2Mac = "";  # optional
    lan3Mac = "";  # optional
  };

  firewall.mullvad = {
    endpoint  = "185.213.154.68";
    port      = 51820;
    serverKey = "...";
    address   = "10.68.1.42/32";
  };
}
```

The Mullvad private key is managed separately via [sops-nix](https://github.com/Mic92/sops-nix). Set `sops.defaultSopsFile` to point at your encrypted `mullvad.yaml`.

## Network layout

```
Port 1 (wan0)  ── upstream ISP/modem (DHCP)
Port 2 (lan1)  ┐
Port 3 (lan2)  ├── bridged as br-lan (192.168.1.1/24)
Port 4 (lan3)  ┘
```

## Project structure

```
flake.nix                    Flake: modules, ISO, test VMs
configuration.nix            Base appliance: SSH, packages, stability
hardware-configuration.nix   Hardware template (users provide their own)
modules/
  options.nix                Configurable firewall.* options
  kernel.nix                 Kernel tuning (BBR, CachyOS)
  network.nix                systemd-networkd: wan0, br-lan bridge
  firewall.nix               nftables rules, NAT, kill switch
  dhcp-dns.nix               Kea DHCP + Unbound DNS-over-TLS
  warp.nix                   Cloudflare WARP + nftables table cleanup
  mullvad.nix                WireGuard tunnel + fwmark routing
  sops.nix                   sops-nix secret wiring
```

## Testing

### Offline integration test

```sh
nix build .#checks.x86_64-linux.firewall-test -L
```

### Black-box e2e test

Boots three QEMU VMs (firewall, client, upstream) with real internet and verifies the full double-tunnel stack: handshake, connectivity, exit identity, WAN leak detection, kill switch, DNS resilience, self-healing after carrier drop, and recovery from 120s internet outage.

Requires sops-encrypted Mullvad credentials. See `tests/e2e/secrets/mullvad.example.yaml` for the schema.

```sh
# One-time: set up age key and encrypt credentials
nix shell nixpkgs#age nixpkgs#sops
age-keygen -o ~/.config/sops/age/keys.txt
# Add pubkey to .sops.yaml, then:
sops tests/e2e/secrets/mullvad.yaml

# Run (first run ~10min, reruns ~8min)
nix shell nixpkgs#sops
./tests/e2e/run-e2e.sh
```

## License

MIT
