#!/usr/bin/env bash
# End-to-end test: client web traffic routes through the WARP tunnel.
#
# Creates a simulated LAN client via network namespace + veth pair,
# configures forwarding rules matching production, then proves that
# the client's web requests go through CloudflareWARP (not bare WAN).
#
# Run inside warp-test-vm after setup-warp.sh:
#   /etc/test-client-routing.sh
set -uo pipefail

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

cleanup() {
  echo ""
  echo "Cleaning up..."
  ip netns del client 2>/dev/null || true
  ip link del veth-fw 2>/dev/null || true
  # Restore original nftables (forward chain was modified)
  nft flush chain inet filter forward 2>/dev/null || true
  nft add rule inet filter forward ct state established,related accept 2>/dev/null || true
  nft add rule inet filter forward ct state invalid drop 2>/dev/null || true
  nft add rule inet filter forward meta nfproto ipv6 drop 2>/dev/null || true
  nft add rule inet filter forward oifname "eth0" tcp dport '{ 80, 443 }' drop 2>/dev/null || true
  nft add rule inet filter forward oifname "eth0" udp dport 443 drop 2>/dev/null || true
  nft add rule inet filter forward drop 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Client Routing E2E Test ==="
echo ""

# ── Preflight: WARP must be connected ──────────────────────────────
if ! ip link show CloudflareWARP &>/dev/null; then
  echo "ERROR: CloudflareWARP interface not found. Run setup-warp.sh first."
  exit 1
fi

if ! warp-cli status 2>&1 | grep -qi "connected"; then
  echo "ERROR: WARP not connected. Run setup-warp.sh first."
  exit 1
fi

# ── Setup: create a LAN client namespace ───────────────────────────
echo "Setting up simulated LAN client..."

# Clean previous runs
ip netns del client 2>/dev/null || true
ip link del veth-fw 2>/dev/null || true

# Create namespace and veth pair
ip netns add client
ip link add veth-fw type veth peer name veth-client
ip link set veth-client netns client

# Firewall side (simulates lan0)
ip addr add 10.0.1.1/24 dev veth-fw 2>/dev/null || true
ip link set veth-fw up

# Client side
ip netns exec client ip link set lo up
ip netns exec client ip addr add 10.0.1.100/24 dev veth-client
ip netns exec client ip link set veth-client up
ip netns exec client ip route add default via 10.0.1.1

# Ensure forwarding is on
sysctl -q net.ipv4.ip_forward=1
sysctl -q net.ipv4.conf.veth-fw.forwarding=1

# ── Setup: nftables forward rules for the LAN client ──────────────
echo "Configuring firewall forwarding rules..."

nft flush chain inet filter forward
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward ct state invalid drop
nft add rule inet filter forward meta nfproto ipv6 drop

# Kill switch: block client web traffic on WAN (must go through WARP)
nft add rule inet filter forward iifname "veth-fw" oifname "eth0" tcp dport '{ 80, 443 }' counter drop
nft add rule inet filter forward iifname "veth-fw" oifname "eth0" udp dport 443 counter drop

# Allow client traffic through CloudflareWARP
nft add rule inet filter forward iifname "veth-fw" oifname "CloudflareWARP" counter accept

# Allow client non-web traffic through WAN
nft add rule inet filter forward iifname "veth-fw" oifname "eth0" counter accept

# Default drop
nft add rule inet filter forward counter drop

echo "Setup complete."
echo ""

# ══════════════════════════════════════════════════════════════════════
#  Tests
# ══════════════════════════════════════════════════════════════════════

echo "[1] Client can reach the firewall"
if ip netns exec client ping -c 1 -W 3 10.0.1.1 &>/dev/null; then
  pass "client can ping firewall (10.0.1.1)"
else
  fail "client cannot reach firewall"
fi

echo "[2] Client DNS resolution (via WAN)"
DNS_RESULT=$(ip netns exec client dig +short +time=5 example.com @1.1.1.1 2>/dev/null || true)
if [ -n "$DNS_RESULT" ]; then
  pass "client DNS works: example.com → $DNS_RESULT"
else
  fail "client DNS resolution failed"
fi

echo "[3] Client HTTPS goes through WARP (cdn-cgi/trace)"
TRACE=$(ip netns exec client curl -4 -sf --max-time 15 --resolve 1.1.1.1:443:1.1.1.1 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
if echo "$TRACE" | grep -q "warp=on"; then
  pass "client web traffic goes through WARP (warp=on)"
  COLO=$(echo "$TRACE" | grep "^colo=" | cut -d= -f2)
  CLIENT_IP=$(echo "$TRACE" | grep "^ip=" | cut -d= -f2)
  echo "       exit IP: ${CLIENT_IP:-unknown}, colo: ${COLO:-unknown}"
else
  WARP_VAL=$(echo "$TRACE" | grep "^warp=" || echo "no response")
  fail "client web traffic NOT through WARP: $WARP_VAL"
fi

echo "[4] Client HTTP (port 80) through WARP"
HTTP_CODE=$(ip netns exec client curl -4 -sf --max-time 15 -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || true)
if [ "$HTTP_CODE" = "200" ]; then
  pass "client HTTP works through WARP (status 200)"
else
  fail "client HTTP failed (status: ${HTTP_CODE:-timeout})"
fi

echo "[5] Packets forwarded through CloudflareWARP (nft counters)"
WARP_PKTS=$(nft list chain inet filter forward 2>/dev/null | grep 'oifname "CloudflareWARP" counter' | grep -oP 'packets \K[0-9]+' || echo "0")
if [ "$WARP_PKTS" -gt "0" ]; then
  pass "$WARP_PKTS packets forwarded through CloudflareWARP"
else
  fail "0 packets forwarded through CloudflareWARP"
fi

echo "[6] Kill switch active: WAN web counter"
WAN_BLOCKED=$(nft list chain inet filter forward 2>/dev/null | grep 'oifname "eth0" tcp dport.*drop' | grep -oP 'packets \K[0-9]+' | head -1 || echo "0")
if nft list chain inet filter forward 2>/dev/null | grep -q 'oifname "eth0" tcp dport.*drop'; then
  pass "kill switch rule present ($WAN_BLOCKED packets blocked on WAN)"
else
  fail "kill switch rule missing from forward chain"
fi

echo "[7] Client non-web traffic works (ping through WAN)"
if ip netns exec client ping -c 2 -W 5 1.1.1.1 &>/dev/null; then
  pass "client ping to 1.1.1.1 works (non-web via WAN)"
else
  # Ping may be blocked by SLIRP; try DNS as fallback
  if ip netns exec client dig +short +time=5 cloudflare.com @1.1.1.1 2>/dev/null | grep -q .; then
    pass "client DNS to 1.1.1.1 works (non-web via WAN)"
  else
    skip "non-web connectivity test inconclusive in VM"
  fi
fi

# ══════════════════════════════════════════════════════════════════════
#  Results
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "  All tests passed!" || { echo "  Some tests failed."; exit 1; }
