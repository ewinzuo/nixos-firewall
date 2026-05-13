#!/usr/bin/env bash
# Black-box assertions for the double-tunnel firewall.
#
# Driven from the host by run-e2e.sh — all state lives inside the three
# QEMU VMs. We poke them via SSH on the mgmt slirp ports.
#
# Test phases:
#   A. Bootstrap WARP on the firewall (registers + connects)
#   B. Tunnel readiness (Mullvad handshake + CloudflareWARP interface)
#   C. Client connectivity through the double tunnel
#   D. Exit identity — confirm the WARP egress is what the public sees
#   E. WAN observer — upstream tcpdump proves only WireGuard leaves wan0
#   F. Kill switch — pause the tunnel and confirm LAN goes dark
#
# Each test prints PASS/FAIL with a one-line reason. Driver exits
# non-zero on any failure.
#
# CI/CD:
#   - Exit code 0 = all pass, 1 = failures
#   - JUnit XML report written to $E2E_REPORT_FILE (default: .runtime/report.xml)
#   - TAP output on stdout when $E2E_TAP=1

set -uo pipefail   # NB: no -e — we want to keep running through failures
                   # so the test report shows the full picture.

PASS=0
FAIL=0
TEST_NUM=0
declare -a FAILURES=()
declare -a TEST_NAMES=()
declare -a TEST_RESULTS=()    # "pass" or "fail"
declare -a TEST_MESSAGES=()
START_TIME=$(date +%s)

ok()    { TEST_NUM=$((TEST_NUM+1)); echo "  PASS: $*"; PASS=$((PASS+1)); TEST_NAMES+=("$*"); TEST_RESULTS+=("pass"); TEST_MESSAGES+=(""); }
bad()   { TEST_NUM=$((TEST_NUM+1)); echo "  FAIL: $*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); TEST_NAMES+=("$*"); TEST_RESULTS+=("fail"); TEST_MESSAGES+=("$*"); }
phase() { echo; echo "── $* ──────────────────────────────────────────"; }

# ── SSH helpers ───────────────────────────────────────────────────────
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNNER_KEY="${RUNNER_KEY:-$HERE/.runtime/runner-key}"
REPORT_FILE="${E2E_REPORT_FILE:-$HERE/.runtime/report.xml}"
if [[ ! -f "$RUNNER_KEY" ]]; then
  echo "ERROR: runner SSH key not found at $RUNNER_KEY" >&2
  echo "Run tests/e2e/run-e2e.sh — it generates the keypair." >&2
  exit 1
fi
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -o ServerAliveInterval=10
          -o LogLevel=ERROR
          -o IdentitiesOnly=yes -i "$RUNNER_KEY")
FW_JUMP_PROXY="ssh ${SSH_OPTS[*]} -p 2223 -W %h:%p root@127.0.0.1"
fw() { ssh "${SSH_OPTS[@]}" -o "ProxyCommand=$FW_JUMP_PROXY" root@192.168.1.1 "$@"; }
cl() { ssh "${SSH_OPTS[@]}" -p 2223 root@127.0.0.1 "$@"; }
up() { ssh "${SSH_OPTS[@]}" -p 2224 root@127.0.0.1 "$@"; }

# ─────────────────────────────────────────────────────────────────────
phase "A0. Connectivity sanity checks"
# ─────────────────────────────────────────────────────────────────────
echo "checking upstream internet access..."
if up 'ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1'; then
  ok "upstream can reach the internet"
else
  bad "upstream has no internet — slirp/host network problem"
fi

echo "checking firewall → upstream (wan0 path)..."
if fw 'ping -c 2 -W 3 10.99.0.1 >/dev/null 2>&1'; then
  ok "firewall can reach upstream via wan0"
else
  bad "firewall cannot reach upstream — vlan1 broken"
fi

echo "checking Mullvad WireGuard handshake..."
fw 'wg show wg-mullvad 2>&1 || true'

echo "checking firewall internet via Mullvad..."
if fw 'ping -c 2 -W 5 1.1.1.1 >/dev/null 2>&1'; then
  ok "firewall has internet (via Mullvad)"
else
  echo "  no internet via Mullvad, trying direct via wan0..."
  fw 'ip route; echo "---"; ip route get 1.1.1.1 2>&1 || true'
  bad "firewall has no internet — Mullvad tunnel or upstream NAT problem"
fi

# ─────────────────────────────────────────────────────────────────────
phase "A1. DNS diagnostics (Unbound → Quad9)"
# ─────────────────────────────────────────────────────────────────────
echo "--- Unbound service status ---"
fw 'systemctl status unbound --no-pager -l 2>&1 | head -30' || true

echo "--- Unbound config (forward-zone) ---"
fw 'grep -A 5 "forward-zone" /etc/unbound/unbound.conf 2>/dev/null || cat /etc/unbound/unbound.conf | tail -20' || true

echo "--- Can firewall reach Quad9 (ICMP)? ---"
fw 'ping -c 3 -W 3 9.9.9.9 2>&1' || true
fw 'ping -c 3 -W 3 149.112.112.112 2>&1' || true

echo "--- Route to Quad9 ---"
fw 'ip route get 9.9.9.9 2>&1' || true

echo "--- Can firewall reach Quad9 port 53 (TCP)? ---"
fw 'timeout 5 bash -c "echo | nc -w 3 9.9.9.9 53 && echo TCP_OK || echo TCP_FAIL" 2>&1' || true

echo "--- Direct dig from firewall to Quad9 ---"
fw 'dig @9.9.9.9 cloudflare.com A +short +timeout=5 +tries=1 2>&1' || true

echo "--- Direct dig from firewall to Quad9 (TCP) ---"
fw 'dig @9.9.9.9 cloudflare.com A +short +timeout=5 +tries=1 +tcp 2>&1' || true

echo "--- dig via Unbound (localhost) ---"
fw 'dig @127.0.0.1 cloudflare.com A +timeout=5 +tries=1 2>&1' || true

echo "--- dig via Unbound from client ---"
cl 'dig @192.168.1.1 cloudflare.com A +timeout=5 +tries=1 2>&1' || true

echo "--- Unbound logs (last 30 lines) ---"
fw 'journalctl -u unbound --no-pager -n 30 2>&1' || true

echo "--- tcpdump: DNS traffic from firewall for 10s ---"
fw 'timeout 10 tcpdump -i any -nn port 53 -c 20 2>&1 &
    sleep 1
    dig @127.0.0.1 example.com +short +timeout=3 +tries=1 2>/dev/null
    dig @9.9.9.9 example.org +short +timeout=3 +tries=1 2>/dev/null
    wait' || true

echo "--- nftables conntrack for port 53 ---"
fw 'conntrack -L -p udp --dport 53 2>&1 | head -20; conntrack -L -p tcp --dport 53 2>&1 | head -10' || true

# ─────────────────────────────────────────────────────────────────────
phase "A. Bootstrap WARP on the firewall"
# ─────────────────────────────────────────────────────────────────────
echo "registering and connecting WARP..."
fw 'set -ex
    systemctl is-active --quiet cloudflare-warp || systemctl start cloudflare-warp
    for i in $(seq 1 30); do
      test -S /run/cloudflare-warp/warp_service && break
      sleep 2
    done
    for attempt in 1 2 3; do
      warp-cli --accept-tos registration delete 2>/dev/null && break
      sleep 2
    done
    sleep 1
    warp-cli --accept-tos registration new
    warp-cli --accept-tos mode tunnel_only
    warp-cli --accept-tos tunnel protocol set MASQUE
    MULLVAD_EP=$(wg show wg-mullvad endpoints 2>/dev/null | awk "{print \$2}" | cut -d: -f1)
    if [ -n "$MULLVAD_EP" ]; then
      echo "Excluding Mullvad endpoint $MULLVAD_EP from WARP split tunnel"
      warp-cli --accept-tos tunnel ip add "$MULLVAD_EP" || true
    fi
    warp-cli --accept-tos connect
'

if fw 'for i in $(seq 1 60); do
         ip link show CloudflareWARP >/dev/null 2>&1 && exit 0
         sleep 2
       done
       exit 1'; then
  ok "CloudflareWARP interface is up"
else
  fw 'warp-cli --accept-tos status 2>&1 || true' || true
  bad "CloudflareWARP interface never appeared"
  echo
  echo "── early-exit: WARP did not come up; downstream tests would all fail ──"
  printf '  - %s\n' "${FAILURES[@]}"
  # Still write report before exiting
  source "$(dirname "$0")/write-report.sh"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────
phase "B. Tunnel readiness — Mullvad handshake"
# ─────────────────────────────────────────────────────────────────────
if fw 'for i in $(seq 1 45); do
         hs=$(wg show wg-mullvad latest-handshakes 2>/dev/null | awk "{print \$2}")
         [ -n "$hs" ] && [ "$hs" != "0" ] && exit 0
         sleep 2
       done
       exit 1'; then
  ok "wg-mullvad has completed a WireGuard handshake"
else
  bad "wg-mullvad never completed a handshake"
fi

if fw 'ip route show 0.0.0.0/1 dev wg-mullvad 2>/dev/null | grep -q wg-mullvad || systemctl is-active --quiet mullvad-routes'; then
  ok "Mullvad routes are active (direct route or service succeeded)"
else
  bad "Mullvad routes not active (mullvad-routes.service did not run?)"
fi

if fw 'for i in $(seq 1 20); do
         warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected" && exit 0
         sleep 2
       done
       exit 1'; then
  ok "warp-cli reports Connected"
else
  bad "warp-cli is not in Connected state"
  fw 'warp-cli --accept-tos status' || true
fi

# ── Precondition: verify tunnels pass traffic + warm up Unbound ───────
# Unbound's first DNS-over-TLS query through the tunnel can be slow
# (TLS handshake to Quad9 via WARP→Mullvad). Prime it here so the
# client DNS test doesn't hit a cold resolver.
TUNNELS_OK=false
if fw 'for i in $(seq 1 8); do
         curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1 && exit 0
         sleep 3
       done
       exit 1'; then
  # Warm up Unbound — keep retrying until DNS-over-TLS to Quad9 through
  # the tunnel actually works. First TLS handshake can take 10-20s.
  # Warm up Unbound (not systemd-resolved). Query 192.168.1.1 directly
  # since 127.0.0.1 hits the systemd-resolved stub, not Unbound.
  # Quad9 is routed through wg-mullvad, which may take a moment.
  echo "  (tunnels up — warming up Unbound via Quad9 → wg-mullvad...)"
  fw 'for i in $(seq 1 20); do
        dig @192.168.1.1 +time=8 +tries=1 cloudflare.com A +short 2>/dev/null | grep -qE "^[0-9]+\." && exit 0
        sleep 2
      done
      echo "WARNING: Unbound warmup failed" >&2
      exit 1' && TUNNELS_OK=true || true
  if $TUNNELS_OK; then
    echo "  (precondition met: tunnels passing traffic, Unbound responding)"
  else
    echo "  WARNING: Unbound not responding — skipping connectivity tests"
  fi
else
  echo "  WARNING: firewall cannot reach internet — skipping connectivity tests"
fi

# ─────────────────────────────────────────────────────────────────────
phase "C. Client connectivity through the double tunnel"
# ─────────────────────────────────────────────────────────────────────
if cl 'ip -4 addr show eth1' | grep -qE 'inet 192\.168\.1\.[0-9]+'; then
  ok "client got a 192.168.1.x lease from the firewall's Kea"
else
  bad "client did NOT receive a 192.168.1.x lease"
  cl 'ip -4 addr show eth1' || true
fi

if cl 'ping -c 2 -W 3 192.168.1.1 >/dev/null'; then
  ok "client can ping the firewall (br-lan IP)"
else
  bad "client cannot ping 192.168.1.1"
fi

if ! $TUNNELS_OK; then
  bad "SKIPPED: client DNS/fetch/identity tests (tunnels not passing traffic)"
else

# Unbound's DNS-over-TLS to Quad9 goes through the tunnel; first query
# may be slow while TLS handshake completes. Try multiple domains as
# fallback in case one is slow/cached differently.
if cl 'for domain in cloudflare.com google.com example.com; do
         for i in 1 2 3; do
           dig @192.168.1.1 +time=5 +tries=1 "$domain" A +short 2>/dev/null | grep -qE "^[0-9]+\." && exit 0
           sleep 2
         done
       done
       exit 1'; then
  ok "client resolves public DNS via firewall Unbound"
else
  bad "client could not resolve any domain via 192.168.1.1"
fi

if cl 'curl -sf --max-time 15 https://cloudflare.com/cdn-cgi/trace >/tmp/trace.txt'; then
  ok "client successfully fetched https://cloudflare.com/cdn-cgi/trace"
else
  bad "client could not fetch through the double tunnel"
fi

# ─────────────────────────────────────────────────────────────────────
phase "D. Exit identity — public sees WARP, not bare upstream"
# ─────────────────────────────────────────────────────────────────────
if cl 'grep -q "^warp=on" /tmp/trace.txt'; then
  ok "Cloudflare reports warp=on — request egressed via WARP"
else
  bad "Cloudflare did not report warp=on (request bypassed WARP?)"
  cl 'grep -E "^(warp|gateway|ip)=" /tmp/trace.txt' || true
fi

SLIRP_PUB="$(up 'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= "/^ip=/{print \$2}"')"
CLIENT_PUB="$(cl 'awk -F= "/^ip=/{print \$2}" /tmp/trace.txt')"
if [[ -n "$SLIRP_PUB" && -n "$CLIENT_PUB" && "$SLIRP_PUB" != "$CLIENT_PUB" ]]; then
  ok "client exit IP ($CLIENT_PUB) differs from upstream slirp IP ($SLIRP_PUB)"
elif [[ -z "$SLIRP_PUB" || -z "$CLIENT_PUB" ]]; then
  bad "could not determine exit IPs (upstream='$SLIRP_PUB' client='$CLIENT_PUB')"
else
  bad "client exit IP equals upstream slirp IP — tunnels were bypassed"
fi

fi  # end TUNNELS_OK gate

# ─────────────────────────────────────────────────────────────────────
phase "E. WAN observer — upstream tcpdump on vlan1"
# ─────────────────────────────────────────────────────────────────────
MULLVAD_ENDPOINT="$(fw 'wg show wg-mullvad endpoints | awk "{print \$2}" | cut -d: -f1')"
MULLVAD_PORT="$(fw 'wg show wg-mullvad endpoints | awk "{print \$2}" | sed "s/.*://"')"

echo "Mullvad endpoint observed on firewall: $MULLVAD_ENDPOINT:$MULLVAD_PORT"

up 'pkill -f "tcpdump -ni eth1" 2>/dev/null; true'
up "tcpdump -ni eth1 -tt -nn 'not arp and not ip6' -w /tmp/vlan1.pcap >/tmp/vlan1.log 2>&1 &"

cl 'for i in $(seq 1 5); do
      curl -sf --max-time 6 https://cloudflare.com/cdn-cgi/trace >/dev/null
      sleep 1
    done' &
TRAFFIC_PID=$!

sleep 10
wait $TRAFFIC_PID 2>/dev/null || true
up 'pkill -f "tcpdump -ni eth1" 2>/dev/null; sleep 1'

PKT_COUNT="$(up 'tcpdump -nr /tmp/vlan1.pcap 2>/dev/null | wc -l')"
if (( PKT_COUNT == 0 )); then
  bad "tcpdump captured 0 packets on vlan1 (capture broken?)"
else
  ok "captured $PKT_COUNT packets on vlan1 during traffic window"
fi

NON_WG_COUNT="$(up "tcpdump -nr /tmp/vlan1.pcap 'not (udp and (host $MULLVAD_ENDPOINT and port $MULLVAD_PORT))' 2>/dev/null | wc -l")"
if (( NON_WG_COUNT == 0 )); then
  ok "every packet on vlan1 is WireGuard to/from Mullvad — no leak"
else
  bad "$NON_WG_COUNT non-WireGuard packets observed on vlan1 — see /tmp/vlan1.pcap on upstream VM"
  up "tcpdump -nr /tmp/vlan1.pcap 'not (udp and (host $MULLVAD_ENDPOINT and port $MULLVAD_PORT))' 2>/dev/null | head -20" || true
fi

# ─────────────────────────────────────────────────────────────────────
phase "F. Kill switch — pause Mullvad and verify LAN goes dark"
# ─────────────────────────────────────────────────────────────────────
echo "stopping wg-mullvad (BindsTo should also stop WARP)..."
fw 'systemctl stop wireguard-wg-mullvad.service' || true
sleep 5

if fw 'systemctl is-active --quiet cloudflare-warp'; then
  bad "cloudflare-warp still running after wg-mullvad stopped (BindsTo not working)"
else
  ok "cloudflare-warp stopped when wg-mullvad stopped (BindsTo kill switch)"
fi

if cl 'curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null'; then
  bad "client could STILL reach the internet with tunnels down — KILL SWITCH FAILED"
else
  ok "client cannot reach internet with tunnels stopped — kill switch holds"
fi

if cl 'nc -z -w 5 1.1.1.1 443'; then
  bad "client could open TCP to 1.1.1.1:443 with tunnels down — kill switch leak"
else
  ok "bare TCP to 1.1.1.1:443 blocked while tunnels are down"
fi

echo "restarting wg-mullvad + WARP..."
fw 'systemctl start wireguard-wg-mullvad.service' || true
fw 'systemctl restart mullvad-routes.service' || true
fw 'systemctl start cloudflare-warp.service' || true

# ─────────────────────────────────────────────────────────────────────
phase "Summary"
# ─────────────────────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))
echo "PASS: $PASS    FAIL: $FAIL    (${ELAPSED}s)"
if (( FAIL > 0 )); then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
fi

# Write JUnit XML report
source "$HERE/write-report.sh"

exit $(( FAIL > 0 ? 1 : 0 ))
