#!/usr/bin/env bash
set -uo pipefail

echo "=== warp-lan-access injection check ==="
nft list chain inet cloudflare-warp input 2>/dev/null | grep 'nixos-override' || echo "(no nixos-override rules injected)"

echo ""
echo "=== warp table ==="
nft list table inet cloudflare-warp 2>&1

echo ""
echo "=== full nft ruleset ==="
nft list ruleset 2>&1

echo ""
echo "=== br-lan addr ==="
ip addr show br-lan 2>&1

echo ""
echo "=== ip route ==="
ip route show 2>&1

echo ""
echo "=== warp-lan-access service ==="
systemctl status warp-lan-access 2>&1

echo ""
echo "=== cloudflare-warp service ==="
systemctl status cloudflare-warp 2>&1

echo ""
echo "=== mullvad-routes service ==="
systemctl status mullvad-routes 2>&1

echo ""
echo "=== wireguard ==="
wg show 2>&1

echo ""
echo "=== systemd-networkd journal (last 20) ==="
journalctl -u systemd-networkd --no-pager -n 20 2>&1

echo ""
echo "=== DONE ==="
