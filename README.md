# nixos-firewall

NixOS-based firewall/router appliance with double-VPN privacy stack. Flash an ISO, run the setup wizard, and you have a hardened perimeter device.

## What it does

```
LAN clients -> br-lan -> CloudflareWARP (MASQUE) -> wg-mullvad (WireGuard) -> wan0 -> Internet
```

- **Destinations** see a Cloudflare/WARP IP
- **Cloudflare** sees a Mullvad exit IP (not your real IP)
- **Your ISP** sees WireGuard to Mullvad (not Cloudflare)
- **Kill switch** drops all unencrypted WAN traffic — if both tunnels fail, nothing leaks

## Features

- **nftables firewall** — default-deny WAN, stateful tracking, bogon filtering, ICMP rate limiting
- **Cloudflare WARP** (MASQUE protocol) — all web traffic tunneled through Cloudflare
- **Mullvad WireGuard** — underlay for WARP; fallback when WARP reconnects
- **Kill switch** — bare WAN traffic is dropped; only VPN-protected traffic leaves the box
- **Kea DHCP + Unbound DNS** — LAN clients get addresses and recursive DNS with Quad9 upstream
- **DNS forcing** — all LAN DNS is redirected to Unbound regardless of client settings
- **3-port LAN bridge** — ports 2-4 are bridged as `br-lan`, acting as a built-in switch
- **Setup wizard** — interactive ISO script configures NICs, Mullvad, SSH keys
- **Remote deploy** — push updates from your desktop with `nixos-rebuild --target-host`
- **Integration tests** — NixOS VM test suite covers firewall, DHCP, DNS, NAT, kill switch

## Hardware requirements

- Any x86_64 machine with 2+ ethernet ports (4 recommended)
- 4GB+ RAM
- Works with common NICs: Intel i226/i210/i350, Intel 10GbE, Realtek GbE

## Quick start

### 1. Build the ISO

```sh
nix build .#firewall-iso
```

Flash `result/iso/*.iso` to a USB stick and boot the target machine from it.

### 2. Run the setup wizard

```sh
/etc/setup-wizard.sh
```

The wizard walks you through:
- Detecting and assigning network ports (WAN + 3 LAN)
- Mullvad WireGuard configuration (endpoint, keys, address)
- Admin username, hostname, and SSH public key

### 3. Partition and install

Partition your disk, mount at `/mnt`, then:

```sh
/etc/install.sh
```

### 4. Reboot and set up WARP

After booting into the installed system:

```sh
sudo /etc/setup-warp.sh
```

This registers with Cloudflare WARP (requires accepting TOS interactively).

Verify:

```sh
curl https://www.cloudflare.com/cdn-cgi/trace/
# Should show warp=on
```

### 5. Copy secrets for remote deploys

From your desktop:

```sh
scp root@<firewall-ip>:/etc/nixos/secrets-config.nix .
```

Now you can push updates remotely:

```sh
nixos-rebuild switch --flake .#firewall --target-host root@<firewall-ip>
```

## Project structure

```
flake.nix                    Flake: firewall, ISO, test VM configs
configuration.nix            Base system: SSH, packages, stability
hardware-configuration.nix   Hardware template (adjust for your box)
modules/
  options.nix                Configurable options (user, MACs, Mullvad)
  kernel.nix                 Kernel tuning (BBR congestion control)
  network.nix                systemd-networkd: wan0, lan1-3, br-lan bridge
  firewall.nix               nftables rules, NAT, kill switch, hardening
  dhcp-dns.nix               Kea DHCP server + Unbound recursive DNS
  warp.nix                   Cloudflare WARP service + LAN rule injection
  mullvad.nix                WireGuard tunnel + handshake-gated routes
scripts/
  setup-wizard.sh            Interactive ISO setup wizard
setup-warp.sh                Post-boot WARP registration
secrets-config.nix.example   Template for machine-specific secrets
tests/
  firewall-test.nix          NixOS VM integration tests
  warp-vm.nix                Live WARP test VM
  test-warp-live.sh          WARP verification script
  test-client-routing.sh     Client routing E2E test
```

## Configuration

All machine-specific values live in `secrets-config.nix` (gitignored). See `secrets-config.nix.example` for the format:

```nix
{ ... }:
{
  firewall.user = {
    name     = "admin";
    hostName = "my-firewall";
    sshKeys  = [ "ssh-ed25519 AAAA..." ];
  };

  firewall.network = {
    wan0Mac = "aa:bb:cc:dd:ee:01";
    lan1Mac = "aa:bb:cc:dd:ee:02";
    lan2Mac = "aa:bb:cc:dd:ee:03";
    lan3Mac = "aa:bb:cc:dd:ee:04";
  };

  firewall.mullvad = {
    endpoint  = "185.213.154.68";
    port      = 51820;
    serverKey = "...";
    address   = "10.68.1.42/32";
  };
}
```

The Mullvad private key is stored separately at `/etc/secrets/mullvad/private-key` (mode 0600).

## Testing

Run the offline integration test suite (no internet required):

```sh
nix build .#checks.x86_64-linux.firewall-test -L
```

For live WARP testing with a VM:

```sh
nix build .#warp-test-vm
./result/bin/run-warp-test-vm
# Inside the VM:
/etc/setup-warp.sh
/etc/test-warp-live.sh
```

## Network layout

```
Port 1 (wan0)  ── upstream ISP/modem (DHCP)
Port 2 (lan1)  ┐
Port 3 (lan2)  ├── bridged as br-lan (192.168.1.1/24)
Port 4 (lan3)  ┘
```

## License

MIT
