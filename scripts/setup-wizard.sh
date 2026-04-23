#!/usr/bin/env bash
# Interactive setup wizard for the NixOS firewall appliance.
# Run this from the ISO before running /etc/install.sh.
#
# What it does:
#   1. Detects network interfaces and lets you assign WAN/LAN roles
#   2. Collects Mullvad WireGuard configuration
#   3. Writes secrets-config.nix and the Mullvad private key
#
# WARP registration is handled separately after first boot via /etc/setup-warp.sh
set -euo pipefail

CONFIG_DIR="/etc/nixos-config"
SECRETS_FILE="$CONFIG_DIR/secrets-config.nix"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           NixOS Firewall Appliance — Setup Wizard           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Phase 0: User & Host ─────────────────────────────────────────────────

echo "=== Phase 0: User & Host ==="
echo ""

read -rp "Admin username [admin]: " USER_NAME
USER_NAME="${USER_NAME:-admin}"
read -rp "System hostname [nixos-firewall]: " HOST_NAME
HOST_NAME="${HOST_NAME:-nixos-firewall}"

echo ""
echo "Paste your SSH public key (e.g. ssh-ed25519 AAAA... user@host)."
echo "This will be the only way to log in — password auth is disabled."
read -rp "SSH public key: " SSH_KEY

if [ -z "$SSH_KEY" ]; then
  echo "WARNING: No SSH key provided. You will need to set one manually."
fi

echo ""

# ── Phase 1: Network Interface Assignment ────────────────────────────────

echo "=== Phase 1: Network Interfaces ==="
echo ""
echo "Detected interfaces:"
echo ""

# Gather physical interfaces (skip lo, virtual, wireless)
mapfile -t IFACES < <(
  ip -o link show | awk -F': ' '{print $2}' | \
    grep -vE '^(lo|docker|veth|br-|wg-|tun|tap|virbr|CloudflareWARP)' | \
    sort
)

if [ ${#IFACES[@]} -lt 4 ]; then
  echo "WARNING: Found only ${#IFACES[@]} interface(s). This appliance expects 4 ports."
  echo "Continuing anyway — you can assign what's available."
  echo ""
fi

# Display interfaces with MAC addresses
for i in "${!IFACES[@]}"; do
  iface="${IFACES[$i]}"
  mac=$(ip link show "$iface" 2>/dev/null | awk '/ether/ {print $2}')
  state=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=state )\w+' || echo "UNKNOWN")
  printf "  [%d] %-12s  MAC: %-17s  State: %s\n" "$((i+1))" "$iface" "${mac:-unknown}" "$state"
done
echo ""

USED_IFACES=""

pick_interface() {
  local role="$1"
  local prompt="$2"
  local selected=""

  while true; do
    read -rp "$prompt [1-${#IFACES[@]}]: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#IFACES[@]}" ]; then
      selected="${IFACES[$((choice-1))]}"
      if echo "$USED_IFACES" | grep -qw "$selected"; then
        echo "  $selected is already assigned. Pick a different port."
        continue
      fi
      local mac
      mac=$(ip link show "$selected" 2>/dev/null | awk '/ether/ {print $2}')
      echo "  → $role = $selected ($mac)"
      eval "${role}_MAC=$mac"
      eval "${role}_IFACE=$selected"
      USED_IFACES="$USED_IFACES $selected"
      return
    fi
    echo "  Invalid choice, try again."
  done
}

echo "Assign each port its role. Tip: plug a cable into one port at a time"
echo "and watch the 'State' column to identify which is which."
echo ""

pick_interface "WAN"  "Select WAN port (upstream ISP/modem)"
echo ""
pick_interface "LAN1" "Select LAN port 1"
echo ""
pick_interface "LAN2" "Select LAN port 2"
echo ""
pick_interface "LAN3" "Select LAN port 3"
echo ""

echo "Interface assignment:"
echo "  WAN  (wan0)  → $WAN_IFACE  ($WAN_MAC)"
echo "  LAN1 (lan1)  → $LAN1_IFACE ($LAN1_MAC)"
echo "  LAN2 (lan2)  → $LAN2_IFACE ($LAN2_MAC)"
echo "  LAN3 (lan3)  → $LAN3_IFACE ($LAN3_MAC)"
echo ""
read -rp "Is this correct? [Y/n]: " confirm
if [[ "$confirm" =~ ^[Nn] ]]; then
  echo "Aborted. Re-run the wizard to try again."
  exit 1
fi

# ── Phase 2: Mullvad WireGuard Configuration ─────────────────────────────

echo ""
echo "=== Phase 2: Mullvad WireGuard ==="
echo ""
echo "You'll need your Mullvad WireGuard config file or account page."
echo "Find these at: https://mullvad.net/en/account/wireguard-config"
echo ""

read -rp "Mullvad server endpoint IP (e.g. 185.213.154.68): " MULLVAD_ENDPOINT
read -rp "Mullvad server port [51820]: " MULLVAD_PORT
MULLVAD_PORT="${MULLVAD_PORT:-51820}"
read -rp "Mullvad server public key: " MULLVAD_SERVER_KEY
read -rp "Your tunnel address (CIDR, e.g. 10.68.1.42/32): " MULLVAD_ADDRESS

echo ""
echo "Enter your Mullvad WireGuard private key."
echo "(This will be stored at /etc/secrets/mullvad/private-key, mode 0600)"
read -rsp "Private key (hidden): " MULLVAD_PRIVATE_KEY
echo ""

echo ""
echo "Mullvad configuration:"
echo "  Endpoint:   $MULLVAD_ENDPOINT:$MULLVAD_PORT"
echo "  Server key: $MULLVAD_SERVER_KEY"
echo "  Address:    $MULLVAD_ADDRESS"
echo "  Private key: (set)"
echo ""
read -rp "Is this correct? [Y/n]: " confirm
if [[ "$confirm" =~ ^[Nn] ]]; then
  echo "Aborted. Re-run the wizard to try again."
  exit 1
fi

# ── Phase 3: Write configuration ─────────────────────────────────────────

echo ""
echo "=== Phase 3: Writing Configuration ==="
echo ""

# Write secrets-config.nix
cat > "$SECRETS_FILE" <<NIXEOF
# Auto-generated by setup-wizard.sh — do not commit to git.
{ ... }:
{
  firewall.user = {
    name     = "$USER_NAME";
    hostName = "$HOST_NAME";
    sshKeys  = [ "$SSH_KEY" ];
  };

  firewall.network = {
    wan0Mac = "$WAN_MAC";
    lan1Mac = "$LAN1_MAC";
    lan2Mac = "$LAN2_MAC";
    lan3Mac = "$LAN3_MAC";
  };

  firewall.mullvad = {
    endpoint  = "$MULLVAD_ENDPOINT";
    port      = $MULLVAD_PORT;
    serverKey = "$MULLVAD_SERVER_KEY";
    address   = "$MULLVAD_ADDRESS";
  };
}
NIXEOF

echo "  ✓ Written: $SECRETS_FILE"

# Write Mullvad private key to temp location (install.sh moves it to /mnt)
echo -n "$MULLVAD_PRIVATE_KEY" > /tmp/mullvad-private-key
chmod 600 /tmp/mullvad-private-key
echo "  ✓ Written: /tmp/mullvad-private-key"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                          ║"
echo "║                                                             ║"
echo "║  Next steps:                                                ║"
echo "║    1. Partition your disk (if not done)                     ║"
echo "║    2. Mount root at /mnt                                    ║"
echo "║    3. Run: /etc/install.sh                                  ║"
echo "║    4. Reboot into installed system                          ║"
echo "║    5. Run: sudo /etc/setup-warp.sh  (accept WARP TOS)      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
