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
#   G. DNS resilience — DNS survives WARP disconnect
#   H. Self-healing — simulate WAN carrier drop, verify auto-recovery
#   I. Internet drop — 120s full outage, verify tunnel + DNS recovery
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

echo "--- fwmark routing diagnostics ---"
echo "  ip rule list:"
fw 'ip rule list' || true
echo "  ip route show table 51820:"
fw 'ip route show table 51820 2>&1' || true
echo "  ip route show table 100:"
fw 'ip route show table 100 2>&1' || true
echo "  wg show wg-mullvad (fwmark check):"
fw 'wg show wg-mullvad 2>&1' || true
echo "  mullvad-routes service status:"
fw 'systemctl status mullvad-routes --no-pager -l 2>&1 | head -30' || true
echo "  mullvad-routes journal:"
fw 'journalctl -u mullvad-routes --no-pager 2>&1 | tail -30' || true
echo "  ip route get 9.9.9.9 (should use wg-mullvad):"
fw 'ip route get 9.9.9.9 2>&1' || true
echo "  ip route get 1.1.1.1 (should use wg-mullvad):"
fw 'ip route get 1.1.1.1 2>&1' || true

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
    # Wait for daemon to accept IPC (socket existing != ready)
    for i in $(seq 1 15); do
      warp-cli --accept-tos status &>/dev/null && break
      sleep 2
    done
    for attempt in 1 2 3 4 5; do
      warp-cli --accept-tos registration delete 2>/dev/null || true
      sleep 2
      warp-cli --accept-tos registration new && break
      echo "registration attempt $attempt failed, restarting daemon..."
      systemctl restart cloudflare-warp
      for i in $(seq 1 15); do
        warp-cli --accept-tos status &>/dev/null && break
        sleep 2
      done
    done
    warp-cli --accept-tos mode tunnel_only
    warp-cli --accept-tos tunnel protocol set MASQUE
    MULLVAD_EP=$(wg show wg-mullvad endpoints 2>/dev/null | awk "{print \$2}" | cut -d: -f1)
    if [ -n "$MULLVAD_EP" ]; then
      echo "Excluding Mullvad endpoint $MULLVAD_EP from WARP split tunnel"
      warp-cli --accept-tos tunnel ip add "$MULLVAD_EP" || true
    fi
    # Exclude Quad9 DNS so Unbound can resolve even when WARP is down
    warp-cli --accept-tos tunnel ip add 9.9.9.11 || true
    warp-cli --accept-tos tunnel ip add 149.112.112.11 || true
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

if fw 'ip route show table 51820 2>/dev/null | grep -q "0.0.0.0/1" || systemctl is-active --quiet mullvad-routes'; then
  ok "Mullvad routes are active (table 51820 or service succeeded)"
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

# Wait for full recovery after the kill switch test before proceeding
# to the self-healing test — we need a known-good baseline.
echo "waiting for tunnels to recover from kill switch test..."
RECOVERED=false
for i in $(seq 1 30); do
  if fw 'wg show wg-mullvad latest-handshakes 2>/dev/null | awk "{print \$2}" | grep -qvE "^0?$"' 2>/dev/null &&
     fw 'warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"' 2>/dev/null &&
     cl 'curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null' 2>/dev/null; then
    RECOVERED=true
    break
  fi
  sleep 5
done

# ─────────────────────────────────────────────────────────────────────
phase "G. DNS resilience — DNS survives WARP disconnect"
# ─────────────────────────────────────────────────────────────────────
# Reproduces the circular-dependency deadlock: WARP goes down, DNS must
# still resolve via Mullvad (Quad9 IPs excluded from WARP split tunnel),
# and WARP must be able to reconnect using that working DNS.

if ! $RECOVERED; then
  bad "SKIPPED: DNS resilience test (tunnels did not recover from kill switch test)"
else

# Exclude Quad9 from WARP split tunnel (mirrors production warp-split-tunnel.service)
fw 'warp-cli --accept-tos tunnel ip add 9.9.9.11 2>/dev/null || true
    warp-cli --accept-tos tunnel ip add 149.112.112.11 2>/dev/null || true'

echo "baseline: verifying DNS works before WARP disconnect..."
if fw 'dig @192.168.1.1 +time=5 +tries=1 cloudflare.com A +short 2>/dev/null | grep -qE "^[0-9]+\."'; then
  ok "pre-disconnect: DNS resolves via Unbound"
else
  bad "pre-disconnect: DNS already broken — cannot test resilience"
fi

echo "disconnecting WARP..."
fw 'warp-cli --accept-tos disconnect' || true
sleep 5

# DNS should still work via Mullvad (Quad9 excluded from WARP tunnel)
if fw 'dig @192.168.1.1 +time=8 +tries=2 example.com A +short 2>/dev/null | grep -qE "^[0-9]+\."'; then
  ok "DNS resolves with WARP disconnected (Quad9 routed via Mullvad)"
else
  bad "DNS FAILED with WARP disconnected — split tunnel exclusion not working"
fi

# Client should also still get DNS (through firewall's Unbound)
if cl 'dig @192.168.1.1 +time=8 +tries=2 example.org A +short 2>/dev/null | grep -qE "^[0-9]+\."'; then
  ok "client DNS resolves with WARP disconnected"
else
  bad "client DNS failed with WARP disconnected"
fi

echo "reconnecting WARP..."
fw 'warp-cli --accept-tos connect' || true

# WARP should recover — it can now resolve its own connectivity-check
# domains because DNS still works via Mullvad
echo "waiting for WARP to reconnect (up to 120s)..."
WARP_RECOVERED=false
for i in $(seq 1 24); do
  if fw 'warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"' 2>/dev/null; then
    WARP_RECOVERED=true
    echo "  WARP reconnected after ~$((i * 5))s"
    break
  fi
  sleep 5
done

if $WARP_RECOVERED; then
  ok "WARP reconnected after disconnect (no DNS deadlock)"
else
  bad "WARP did NOT reconnect — DNS deadlock may still exist"
  fw 'warp-cli --accept-tos status 2>&1' || true
fi

# Verify full chain is back
if $WARP_RECOVERED; then
  if cl 'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"'; then
    ok "post-reconnect: client traffic egresses via WARP"
  else
    bad "post-reconnect: client traffic NOT going through WARP"
  fi
fi

fi  # end RECOVERED gate

# ─────────────────────────────────────────────────────────────────────
phase "H. Self-healing — WAN carrier drop recovery"
# ─────────────────────────────────────────────────────────────────────
# Simulates the production failure: wan0 briefly loses carrier (ISP
# modem reboot, cable glitch, igc driver hiccup), then comes back.
# The system must re-establish Mullvad handshake, reinstall routes,
# reconnect WARP, and restore client internet — without manual
# intervention.
#
# Method: bring down eth1 on the upstream VM (kills the vlan1 link),
# wait for the firewall to notice, then bring it back up and verify
# full recovery.

if ! $RECOVERED; then
  bad "SKIPPED: self-healing tests (tunnels did not recover from kill switch test)"
else

echo "verifying baseline: client has internet before disruption..."
if cl 'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1'; then
  ok "pre-disruption baseline: client has internet"
else
  bad "SKIPPED: pre-disruption baseline failed — cannot test self-healing"
fi

echo "simulating WAN carrier drop (upstream eth1 down)..."
up 'ip link set eth1 down'
sleep 15

echo "verifying firewall lost connectivity..."
if fw 'ping -c 2 -W 3 10.99.0.1 >/dev/null 2>&1'; then
  echo "  WARNING: firewall can still reach upstream (carrier drop may not have propagated)"
else
  echo "  confirmed: firewall cannot reach upstream"
fi

echo "restoring WAN (upstream eth1 up)..."
up 'ip link set eth1 up'
sleep 5

echo "waiting for self-healing (up to 180s)..."
HEALED=false
for i in $(seq 1 36); do
  # Check: wan0 has IP, Mullvad handshake is RECENT (< 180s), client has internet
  HS_AGE=""
  if fw 'ip -4 addr show wan0 2>/dev/null | grep -q "inet "' 2>/dev/null; then
    HS=$(fw 'wg show wg-mullvad latest-handshakes 2>/dev/null | awk "{print \$2}"' 2>/dev/null || true)
    NOW=$(date +%s)
    if [ -n "$HS" ] && [ "$HS" != "0" ]; then
      HS_AGE=$((NOW - HS))
      if [ "$HS_AGE" -lt 180 ] &&
         cl 'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace >/dev/null' 2>/dev/null; then
        HEALED=true
        echo "  healed after ~$((i * 5))s (handshake ${HS_AGE}s ago)"
        break
      fi
    fi
  fi
  sleep 5
done

if $HEALED; then
  ok "system self-healed after WAN carrier drop"
else
  bad "system did NOT self-heal after WAN carrier drop (180s timeout)"
  echo "  --- post-disruption diagnostics ---"
  fw 'echo "wan0:"; ip -br a show wan0; echo "wg-mullvad:"; wg show wg-mullvad 2>&1 | head -5; echo "routes:"; ip route | head -5; echo "warp:"; warp-cli --accept-tos status 2>&1 | head -3' || true
fi

# Verify the full chain recovered
if $HEALED; then
  echo "  --- post-recovery diagnostics ---"
  fw 'echo "table 51820:"; ip route show table 51820 2>&1; echo "rules:"; ip rule show 2>&1 | grep -E "fwmark|51820" ; echo "default:"; ip route show default 2>&1; echo "warp:"; warp-cli --accept-tos status 2>&1 | head -3; echo "services:"; systemctl is-active wireguard-wg-mullvad mullvad-routes cloudflare-warp 2>&1' 2>/dev/null || true

  if fw 'ip route show table 51820 2>/dev/null | grep -q "0.0.0.0/1"'; then
    ok "post-recovery: Mullvad tunnel routes present (table 51820)"
  else
    bad "post-recovery: Mullvad tunnel routes missing (table 51820)"
  fi

  # WARP reconnects with exponential backoff after carrier drop — allow up to 120s
  WARP_POST_HEAL=false
  for i in $(seq 1 24); do
    if cl 'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"' 2>/dev/null; then
      WARP_POST_HEAL=true
      echo "  WARP reconnected after ~$((i * 5))s"
      break
    fi
    sleep 5
  done
  if $WARP_POST_HEAL; then
    ok "post-recovery: client traffic egresses via WARP"
  else
    bad "post-recovery: client traffic NOT going through WARP"
    fw 'warp-cli --accept-tos status 2>&1' 2>/dev/null || true
  fi
fi

fi  # end RECOVERED gate

# ─────────────────────────────────────────────────────────────────────
phase "I. Internet drop — 120s outage recovery"
# ─────────────────────────────────────────────────────────────────────
# Simulate a complete internet outage by blocking all traffic on the
# upstream VM's internet-facing interface (eth0/slirp). After 120s,
# restore and verify Mullvad tunnel + DNS self-heal.

if ! $RECOVERED; then
  bad "SKIPPED: internet drop test (tunnels did not recover from kill switch test)"
else

echo "blocking all internet on upstream VM for 120s..."
up 'nft add table inet blackhole
    nft add chain inet blackhole input "{ type filter hook input priority -1; policy accept; }"
    nft add chain inet blackhole output "{ type filter hook output priority -1; policy accept; }"
    nft add rule inet blackhole input iifname "eth0" drop
    nft add rule inet blackhole output oifname "eth0" drop
    echo "blocked"' 2>&1

sleep 120

echo "restoring internet..."
up 'nft delete table inet blackhole; echo "restored"' 2>&1

echo "waiting for Mullvad tunnel to recover (up to 120s)..."
TUNNEL_RECOVERED=false
for i in $(seq 1 24); do
  sleep 5
  HS=$(fw 'wg show wg-mullvad latest-handshakes 2>/dev/null | awk "{print \$2}"' 2>/dev/null || true)
  NOW=$(date +%s)
  if [ -n "$HS" ] && [ "$HS" != "0" ]; then
    AGE=$((NOW - HS))
    if [ "$AGE" -lt 30 ]; then
      echo "  tunnel recovered after ~$((i * 5))s (handshake ${AGE}s ago)"
      TUNNEL_RECOVERED=true
      break
    fi
  fi
done

if $TUNNEL_RECOVERED; then
  ok "Mullvad tunnel re-established after 120s internet drop"
else
  bad "Mullvad tunnel did not recover after 120s internet drop"
fi

fw 'systemctl restart unbound' 2>/dev/null
sleep 3
UNBOUND_RECOVERED=false
for i in $(seq 1 6); do
  if fw 'dig @127.0.0.1 +time=10 +tries=1 github.com A +short 2>/dev/null | grep -qE "^[0-9]+\."'; then
    UNBOUND_RECOVERED=true
    break
  fi
  sleep 5
done

if $UNBOUND_RECOVERED; then
  ok "Unbound DoT recovered after 120s internet drop"
else
  bad "Unbound DoT did not recover after 120s internet drop"
fi

if $UNBOUND_RECOVERED; then
  if cl 'dig @192.168.1.1 +time=5 +tries=1 example.com A +short 2>/dev/null | grep -qE "^[0-9]+\."'; then
    ok "client DNS works after 120s internet drop recovery"
  else
    bad "client DNS broken after 120s internet drop recovery"
  fi
fi

fi  # end RECOVERED gate

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
