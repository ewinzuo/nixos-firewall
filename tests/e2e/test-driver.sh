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
# Each test prints PASS/FAIL/SKIP with a one-line reason. Driver exits
# non-zero on any failure.

set -uo pipefail   # NB: no -e — we want to keep running through failures
                   # so the test report shows the full picture.

PASS=0
FAIL=0
declare -a FAILURES=()

ok()    { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()   { echo "  FAIL: $*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); }
phase() { echo; echo "── $* ──────────────────────────────────────────"; }

# ── SSH helpers ───────────────────────────────────────────────────────
# RUNNER_KEY is provided by run-e2e.sh via the environment; fall back to
# the conventional path under .runtime so the driver can be invoked
# standalone for ad-hoc poking.
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNNER_KEY="${RUNNER_KEY:-$HERE/.runtime/runner-key}"
if [[ ! -f "$RUNNER_KEY" ]]; then
  echo "ERROR: runner SSH key not found at $RUNNER_KEY" >&2
  echo "Run tests/e2e/run-e2e.sh — it generates the keypair." >&2
  exit 1
fi
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -o ServerAliveInterval=10
          -o LogLevel=ERROR
          -o IdentitiesOnly=yes -i "$RUNNER_KEY")
# Firewall is reached via the client VM as a jump host — it sits on br-lan
# which nftables allows for SSH, and avoids any mgmt-interface hacks.
# Use explicit ProxyCommand (not -J) so SSH_OPTS apply to the inner
# jump connection too — otherwise the jump child re-prompts for
# host-key verification.
FW_JUMP_PROXY="ssh ${SSH_OPTS[*]} -p 2223 -W %h:%p root@127.0.0.1"
fw() { ssh "${SSH_OPTS[@]}" -o "ProxyCommand=$FW_JUMP_PROXY" root@192.168.1.1 "$@"; }
cl() { ssh "${SSH_OPTS[@]}" -p 2223 root@127.0.0.1 "$@"; }
up() { ssh "${SSH_OPTS[@]}" -p 2224 root@127.0.0.1 "$@"; }

# ─────────────────────────────────────────────────────────────────────
phase "A. Bootstrap WARP on the firewall"
# ─────────────────────────────────────────────────────────────────────
# warp-svc needs a one-time registration + tunnel mode + connect. The
# production setup-warp.sh script does exactly this; we run an inline
# equivalent because the production script isn't shipped into the VM.
echo "registering and connecting WARP (this can take 30-60s)..."
fw 'set -ex
    systemctl is-active --quiet cloudflare-warp || systemctl start cloudflare-warp
    # Wait for the warp-svc control socket — not warp-cli status, which fails
    # before TOS is accepted and gives a misleading "not ready" signal.
    for i in $(seq 1 60); do
      test -S /run/cloudflare-warp/warp_service && break
      sleep 2
    done
    # Clear any stale state, retry a few times since the daemon may need
    # a moment after socket creation to be fully ready for commands.
    for attempt in 1 2 3; do
      warp-cli --accept-tos registration delete 2>/dev/null && break
      sleep 2
    done
    sleep 1
    warp-cli --accept-tos registration new
    warp-cli --accept-tos mode tunnel_only
    warp-cli --accept-tos tunnel protocol set MASQUE
    # Exclude Mullvad endpoint from WARP tunnel so WireGuard UDP packets
    # bypass WARP firewall rules. Must happen BEFORE connect, otherwise
    # WARP kill switch blocks Mullvad and both tunnels die.
    MULLVAD_EP=$(wg show wg-mullvad endpoints 2>/dev/null | awk "{print \$2}" | cut -d: -f1)
    if [ -n "$MULLVAD_EP" ]; then
      echo "Excluding Mullvad endpoint $MULLVAD_EP from WARP split tunnel"
      warp-cli --accept-tos tunnel ip add "$MULLVAD_EP" || true
    else
      echo "WARNING: could not determine Mullvad endpoint"
    fi
    warp-cli --accept-tos connect
'

if fw 'for i in $(seq 1 90); do
         ip link show CloudflareWARP >/dev/null 2>&1 && exit 0
         sleep 2
       done
       exit 1'; then
  ok "CloudflareWARP interface is up"
else
  # Dump diagnostics before bailing
  echo "── WARP debug ──"
  fw 'warp-cli --accept-tos status 2>&1 || true; echo "---"; ip link show 2>&1; echo "---"; journalctl -u cloudflare-warp --no-pager -n 40 2>&1 || true; echo "---internet---"; ping -c 2 -W 3 1.1.1.1 2>&1 || true' || true
  bad "CloudflareWARP interface never appeared"
  echo
  echo "── early-exit: WARP did not come up; downstream tests would all fail ──"
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────
phase "B. Tunnel readiness — Mullvad handshake"
# ─────────────────────────────────────────────────────────────────────
if fw 'for i in $(seq 1 30); do
         hs=$(wg show wg-mullvad latest-handshakes 2>/dev/null | awk "{print \$2}")
         [ -n "$hs" ] && [ "$hs" != "0" ] && exit 0
         sleep 2
       done
       exit 1'; then
  ok "wg-mullvad has completed a WireGuard handshake"
else
  bad "wg-mullvad never completed a handshake"
fi

# When WARP is active it installs its own routes (table 65743) that may
# displace the explicit 0.0.0.0/1 via wg-mullvad from the main table.
# Check either the main-table route OR that mullvad-routes.service
# succeeded (the WAN observer in phase E is the real proof).
if fw 'ip route show 0.0.0.0/1 dev wg-mullvad 2>/dev/null | grep -q wg-mullvad || systemctl is-active --quiet mullvad-routes'; then
  ok "Mullvad routes are active (direct route or service succeeded)"
else
  bad "Mullvad routes not active (mullvad-routes.service did not run?)"
fi

# WARP should be reporting Connected — wait up to 60s for it to settle
if fw 'for i in $(seq 1 30); do
         warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected" && exit 0
         sleep 2
       done
       exit 1'; then
  ok "warp-cli reports Connected"
else
  bad "warp-cli is not in Connected state"
  fw 'warp-cli --accept-tos status' || true
fi

# ─────────────────────────────────────────────────────────────────────
phase "C. Client connectivity through the double tunnel"
# ─────────────────────────────────────────────────────────────────────
# 1. DHCP gave the client a 192.168.1.x lease via Kea
if cl 'ip -4 addr show eth1' | grep -qE 'inet 192\.168\.1\.[0-9]+'; then
  ok "client got a 192.168.1.x lease from the firewall's Kea"
else
  bad "client did NOT receive a 192.168.1.x lease"
  cl 'ip -4 addr show eth1' || true
fi

# 2. Client can ping the firewall LAN address
if cl 'ping -c 2 -W 3 192.168.1.1 >/dev/null'; then
  ok "client can ping the firewall (br-lan IP)"
else
  bad "client cannot ping 192.168.1.1"
fi

# 3. Client can resolve a public name through Unbound on the firewall
if cl 'dig @192.168.1.1 +time=5 +tries=2 cloudflare.com A +short' | grep -qE '^[0-9]+\.'; then
  ok "client resolves cloudflare.com via firewall DNS (Unbound)"
else
  bad "client could not resolve cloudflare.com via 192.168.1.1"
fi

# 4. Client can fetch a real HTTP page — proof end-to-end internet works
if cl 'curl -sf --max-time 20 https://www.cloudflare.com/cdn-cgi/trace/ >/tmp/trace.txt'; then
  ok "client successfully fetched https://cloudflare.com/cdn-cgi/trace/"
else
  bad "client could not fetch through the double tunnel"
fi

# ─────────────────────────────────────────────────────────────────────
phase "D. Exit identity — public sees WARP, not bare upstream"
# ─────────────────────────────────────────────────────────────────────
# The trace endpoint reports `warp=on` if Cloudflare sees the request
# as having come through WARP — which it only does if our packets
# actually went through the WARP tunnel.
if cl 'grep -q "^warp=on" /tmp/trace.txt'; then
  ok "Cloudflare reports warp=on — request egressed via WARP"
else
  bad "Cloudflare did not report warp=on (request bypassed WARP?)"
  cl 'grep -E "^(warp|gateway|ip)=" /tmp/trace.txt' || true
fi

# Confirm the exit IP is NOT the upstream VM's public slirp IP. The
# slirp NAT presents the host's public address; if we ever see that as
# the trace's "ip=" line, traffic skipped both tunnels.
SLIRP_PUB="$(up 'curl -sf --max-time 10 https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | awk -F= "/^ip=/{print \$2}"')"
CLIENT_PUB="$(cl 'awk -F= "/^ip=/{print \$2}" /tmp/trace.txt')"
if [[ -n "$SLIRP_PUB" && -n "$CLIENT_PUB" && "$SLIRP_PUB" != "$CLIENT_PUB" ]]; then
  ok "client exit IP ($CLIENT_PUB) differs from upstream slirp IP ($SLIRP_PUB)"
elif [[ -z "$SLIRP_PUB" || -z "$CLIENT_PUB" ]]; then
  bad "could not determine exit IPs (upstream='$SLIRP_PUB' client='$CLIENT_PUB')"
else
  bad "client exit IP equals upstream slirp IP — tunnels were bypassed"
fi

# ─────────────────────────────────────────────────────────────────────
phase "E. WAN observer — upstream tcpdump on vlan1"
# ─────────────────────────────────────────────────────────────────────
# Sniff vlan1 (eth1) for 15 seconds while the client makes traffic.
# Every packet between the firewall and the upstream MUST be UDP to/from
# the Mullvad endpoint port. Anything else means raw LAN traffic leaked
# through wan0 — the central thing we are testing for.
# Recover endpoint:port from the live wireguard config — that way this
# test stays correct even if Mullvad creds are rotated between runs.
MULLVAD_ENDPOINT="$(fw 'wg show wg-mullvad endpoints | awk "{print \$2}" | cut -d: -f1')"
MULLVAD_PORT="$(fw 'wg show wg-mullvad endpoints | awk "{print \$2}" | sed "s/.*://"')"

echo "Mullvad endpoint observed on firewall: $MULLVAD_ENDPOINT:$MULLVAD_PORT"

up 'pkill -f "tcpdump -ni eth1" 2>/dev/null; true'
up "tcpdump -ni eth1 -tt -nn 'not arp and not ip6' -w /tmp/vlan1.pcap >/tmp/vlan1.log 2>&1 &"

# Generate sustained traffic from the client during the capture window.
cl 'for i in $(seq 1 5); do
      curl -sf --max-time 8 https://www.cloudflare.com/cdn-cgi/trace/ >/dev/null
      sleep 1
    done' &
TRAFFIC_PID=$!

sleep 15
wait $TRAFFIC_PID 2>/dev/null || true
up 'pkill -f "tcpdump -ni eth1" 2>/dev/null; sleep 1'

# Did we capture anything at all?
PKT_COUNT="$(up 'tcpdump -nr /tmp/vlan1.pcap 2>/dev/null | wc -l')"
if (( PKT_COUNT == 0 )); then
  bad "tcpdump captured 0 packets on vlan1 (capture broken?)"
else
  ok "captured $PKT_COUNT packets on vlan1 during traffic window"
fi

# Every packet must be UDP to/from $MULLVAD_ENDPOINT:$MULLVAD_PORT
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
echo "stopping wg-mullvad..."
fw 'systemctl stop wireguard-wg-mullvad.service' || true
sleep 3

# Without the tunnel, client traffic must NOT reach the internet.
if cl 'curl -sf --max-time 8 https://www.cloudflare.com/cdn-cgi/trace/ >/dev/null'; then
  bad "client could STILL reach the internet with wg-mullvad down — KILL SWITCH FAILED"
else
  ok "client cannot reach internet with wg-mullvad stopped — kill switch holds"
fi

# Bare TCP to wan-side IPs must also fail (no route, or dropped).
if cl 'nc -z -w 3 1.1.1.1 443'; then
  bad "client could open TCP to 1.1.1.1:443 with tunnel down — kill switch leak"
else
  ok "bare TCP to 1.1.1.1:443 blocked while tunnel is down"
fi

echo "restarting wg-mullvad..."
fw 'systemctl start wireguard-wg-mullvad.service' || true
fw 'systemctl restart mullvad-routes.service' || true

# ─────────────────────────────────────────────────────────────────────
phase "Summary"
# ─────────────────────────────────────────────────────────────────────
echo "PASS: $PASS    FAIL: $FAIL"
if (( FAIL > 0 )); then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
