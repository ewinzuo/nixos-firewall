#!/usr/bin/env bash
# Set up Cloudflare WARP with MASQUE protocol.
# Run this once after deploying NixOS to the box.
set -euo pipefail

echo "=== Cloudflare WARP Setup (MASQUE) ==="
echo ""

# Check warp-svc is running
if ! systemctl is-active --quiet cloudflare-warp; then
  echo "Starting cloudflare-warp service..."
  sudo systemctl start cloudflare-warp
fi

echo "[1/4] Registering with Cloudflare WARP..."
# Force-clean any stale registration state
sudo warp-cli registration delete 2>/dev/null || true
sudo systemctl stop cloudflare-warp 2>/dev/null || true
sudo rm -rf /var/lib/cloudflare-warp/reg.json 2>/dev/null || true
sudo systemctl start cloudflare-warp

# Wait for the IPC socket to appear
echo "Waiting for warp-svc daemon..."
for i in $(seq 1 30); do
  if warp-cli status &>/dev/null; then
    echo "Daemon is ready."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: warp-svc did not become ready after 30s"
    echo "Check: journalctl -u cloudflare-warp --no-pager -n 30"
    exit 1
  fi
  sleep 1
done

# Register
sudo warp-cli --accept-tos registration new 2>/dev/null || sudo warp-cli registration new

echo ""
echo "[2/4] Setting tunnel mode to tunnel_only (no DNS hijack)..."
sudo warp-cli mode tunnel_only

echo ""
echo "[3/4] Enabling MASQUE protocol..."
sudo warp-cli tunnel protocol set MASQUE

echo ""
echo "[4/4] Connecting..."
sudo warp-cli connect

echo "Waiting for tunnel..."
for i in $(seq 1 15); do
  if ip link show CloudflareWARP &>/dev/null; then
    echo "CloudflareWARP interface is up!"
    break
  fi
  sleep 2
done

echo ""
echo "=== Verifying ==="
echo ""

echo "Status:"
warp-cli status
echo ""

echo "Interface:"
ip addr show CloudflareWARP 2>/dev/null || echo "WARNING: CloudflareWARP interface not found yet"
echo ""

echo "WARP trace (should show warp=on):"
curl -sf --max-time 10 https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | grep -E '(warp|gateway)' || echo "WARNING: could not verify WARP connection"

echo ""
echo "=== Done ==="
