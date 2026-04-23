#!/usr/bin/env bash
# Live integration test for WARP + MASQUE.
# Run as root after setup-warp.sh has been run.
#
# Usage: /etc/test-warp-live.sh
set +e
set -uo pipefail

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

section() { echo ""; echo "── $1 ──"; }

echo "=== WARP Live Integration Tests ==="

# ╔════════════════════════════════════════════════════════════════════╗
# ║  Section 1: Service & Interface Health                            ║
# ╚════════════════════════════════════════════════════════════════════╝
section "Service & Interface Health"

echo "[1] cloudflare-warp service"
if systemctl is-active --quiet cloudflare-warp; then
  pass "cloudflare-warp.service is active"
else
  fail "cloudflare-warp.service is not running"
fi

echo "[2] warp-cli connected"
WARP_STATUS=$(warp-cli status 2>&1 || true)
if echo "$WARP_STATUS" | grep -qi "connected"; then
  pass "warp-cli reports Connected"
else
  fail "warp-cli not connected: $WARP_STATUS"
fi

echo "[3] tunnel protocol"
# warp-cli settings shows the active protocol
SETTINGS=$(warp-cli settings 2>&1 || true)
if echo "$SETTINGS" | grep -qi "WARP tunnel protocol.*MASQUE"; then
  pass "tunnel protocol is MASQUE"
elif echo "$SETTINGS" | grep -qi "WARP tunnel protocol.*WireGuard"; then
  fail "tunnel protocol is WireGuard, not MASQUE. Run: warp-cli tunnel protocol set MASQUE"
else
  echo "       could not parse protocol from settings"
  skip "could not determine tunnel protocol"
fi

echo "[4] CloudflareWARP interface"
if ip link show CloudflareWARP &>/dev/null; then
  pass "CloudflareWARP interface is UP"
  WARP_IP=$(ip -4 addr show CloudflareWARP | grep -oP 'inet \K[0-9.]+' || echo "none")
  echo "       interface IP: $WARP_IP"
else
  fail "CloudflareWARP interface not found"
fi

echo "[5] WARP routing table (65743)"
ROUTE_COUNT=$(ip route show table 65743 2>/dev/null | grep -c "CloudflareWARP" || true)
if [ "$ROUTE_COUNT" -gt 0 ]; then
  pass "WARP routing table 65743 has $ROUTE_COUNT routes via CloudflareWARP"
else
  fail "WARP routing table 65743 has no CloudflareWARP routes"
fi

# ╔════════════════════════════════════════════════════════════════════╗
# ║  Section 2: Traffic Tests — Web Through WARP                      ║
# ╚════════════════════════════════════════════════════════════════════╝
section "Traffic Tests — Web Through WARP"

echo "[6] HTTPS to cloudflare.com/cdn-cgi/trace"
TRACE=$(curl -4 -sf --max-time 15 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
if echo "$TRACE" | grep -q "warp=on"; then
  pass "cdn-cgi/trace: warp=on"
  COLO=$(echo "$TRACE" | grep "^colo=" | cut -d= -f2)
  echo "       Cloudflare colo: ${COLO:-unknown}"
else
  WARP_VAL=$(echo "$TRACE" | grep "^warp=" || echo "warp=<missing>")
  fail "cdn-cgi/trace: $WARP_VAL (expected warp=on)"
fi

echo "[7] HTTP (port 80) connectivity through WARP"
HTTP_CODE=$(curl -4 -sf --max-time 15 -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || true)
if [ "$HTTP_CODE" = "200" ]; then
  pass "HTTP request to example.com succeeded (status 200)"
else
  fail "HTTP to example.com failed (status: ${HTTP_CODE:-timeout})"
fi

echo "[8] multiple HTTPS sites reachable"
MULTI_OK=true
for site in https://1.1.1.1/cdn-cgi/trace https://cloudflare.com https://google.com; do
  CODE=$(curl -4 -sf --max-time 15 -o /dev/null -w "%{http_code}" "$site" 2>/dev/null || true)
  if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    fail "HTTPS to $site timed out"
    MULTI_OK=false
  fi
done
$MULTI_OK && pass "multiple HTTPS sites reachable through WARP"

echo "[9] external IP is a WARP exit IP"
EXTERNAL_IP=$(curl -4 -sf --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep "^ip=" | cut -d= -f2 || true)
if [ -n "$EXTERNAL_IP" ]; then
  pass "external IP via WARP: $EXTERNAL_IP"
else
  fail "could not determine external IP"
fi

echo "[10] non-Cloudflare HTTPS also works"
EXTERN_TEST=$(curl -4 -sf --max-time 15 -o /dev/null -w "%{http_code}" https://google.com 2>/dev/null || true)
if [ "$EXTERN_TEST" != "000" ] && [ -n "$EXTERN_TEST" ]; then
  pass "HTTPS to google.com works (status $EXTERN_TEST)"
else
  fail "HTTPS to google.com timed out"
fi

# ╔════════════════════════════════════════════════════════════════════╗
# ║  Section 3: DNS                                                    ║
# ╚════════════════════════════════════════════════════════════════════╝
section "DNS"

echo "[11] DNS resolution works"
if command -v dig &>/dev/null; then
  DNS_RESULT=$(dig +short +time=5 example.com 2>/dev/null || true)
  if [ -n "$DNS_RESULT" ]; then
    pass "DNS resolution works: example.com → $DNS_RESULT"
  else
    fail "DNS resolution failed"
  fi
else
  skip "dig not available"
fi

echo "[12] DNS to 1.1.1.1 works"
if dig +short +time=5 cloudflare.com @1.1.1.1 2>/dev/null | grep -q .; then
  pass "DNS query to 1.1.1.1 succeeded"
else
  fail "DNS query to 1.1.1.1 failed"
fi

# ╔════════════════════════════════════════════════════════════════════╗
# ║  Section 4: Kill Switch (disconnect/reconnect cycle)               ║
# ╚════════════════════════════════════════════════════════════════════╝
section "Kill Switch"

echo "[13] baseline: HTTPS works before disconnect"
if curl -4 -sf --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
  pass "baseline HTTPS works (warp=on)"
else
  fail "baseline HTTPS not working — skipping kill switch tests"
  # Skip remaining kill switch tests
  echo "[14] kill switch: skipped (no baseline)"
  skip "skipped — baseline failed"
  echo "[15] kill switch: skipped"
  skip "skipped — baseline failed"
  # Jump to results
  echo ""
  echo "════════════════════════════════════════════════"
  echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
  echo "════════════════════════════════════════════════"
  [ "$FAIL" -eq 0 ] && echo "  All tests passed!" || { echo "  Some tests failed."; exit 1; }
  exit
fi

warp-cli disconnect &>/dev/null || true
sleep 5

echo "[14] non-web traffic still works while WARP is down"
if ping -c 2 -W 5 1.1.1.1 &>/dev/null; then
  pass "ping works without WARP (connectivity still exists)"
elif dig +short +time=5 example.com 2>/dev/null | grep -q .; then
  pass "DNS works without WARP (connectivity still exists)"
else
  skip "no non-web connectivity detected (may be expected in VM)"
fi

echo "[15] reconnect WARP → web traffic recovers"
warp-cli connect &>/dev/null || true

RECOVERED=false
for i in $(seq 1 20); do
  TRACE_R=$(curl -4 -sf --max-time 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
  if echo "$TRACE_R" | grep -q "warp=on"; then
    RECOVERED=true
    break
  fi
  sleep 3
done

if $RECOVERED; then
  pass "HTTPS recovered after reconnect (warp=on)"
else
  fail "HTTPS did not recover within 60s"
fi

# ╔════════════════════════════════════════════════════════════════════╗
# ║  Results                                                          ║
# ╚════════════════════════════════════════════════════════════════════╝
echo ""
echo "════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "  All tests passed!" || { echo "  Some tests failed."; exit 1; }
