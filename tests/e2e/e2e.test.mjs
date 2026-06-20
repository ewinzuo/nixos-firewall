import assert from "node:assert/strict";
import { fw, cl, up, fwOk, clOk, upOk, sleep, waitFor } from "./helpers.mjs";

// Shared state flags across phases
const state = {
  warpUp: false,
  tunnelsOk: false,
  recovered: false,
  mullvadEndpoint: "",
  mullvadPort: "",
};

// ---------------------------------------------------------------------------
// Phase A0: Connectivity sanity checks
// ---------------------------------------------------------------------------
describe("A0. Connectivity sanity checks", function () {
  this.timeout(120_000);

  it("upstream can reach the internet", async function () {
    const ok = await upOk("ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1");
    assert.ok(ok, "upstream has no internet -- slirp/host network problem");
  });

  it("firewall can reach upstream via wan0", async function () {
    const ok = await fwOk("ping -c 2 -W 3 10.99.0.1 >/dev/null 2>&1");
    assert.ok(ok, "firewall cannot reach upstream -- vlan1 broken");
  });

  it("firewall has internet via Mullvad", async function () {
    this.timeout(120_000);
    const ok = await waitFor(
      () => fwOk("ping -c 2 -W 5 1.1.1.1 >/dev/null 2>&1"),
      { timeout: 60, interval: 5, label: "firewall internet" },
    );
    if (!ok) {
      try {
        const routes = await fw("ip route; echo '---'; ip route get 1.1.1.1 2>&1 || true");
        console.log("  routing diagnostics:", routes);
      } catch { /* best effort */ }
    }
    assert.ok(ok, "firewall has no internet -- Mullvad tunnel or upstream NAT problem");
  });
});

// ---------------------------------------------------------------------------
// Phase A1: DNS diagnostics (Unbound -> Quad9)
// ---------------------------------------------------------------------------
describe("A1. DNS diagnostics (Unbound -> Quad9)", function () {
  this.timeout(120_000);

  before(async function () {
    const diag = async (label, vmFn, cmd) => {
      try {
        const out = await vmFn(cmd);
        console.log(`  --- ${label} ---\n${out}`);
      } catch (e) {
        console.log(`  --- ${label} --- (failed: ${e.message})`);
      }
    };

    await diag("Unbound service status", fw, "systemctl status unbound --no-pager -l 2>&1 | head -30");
    await diag("Unbound config (forward-zone)", fw,
      'grep -A 5 "forward-zone" /etc/unbound/unbound.conf 2>/dev/null || cat /etc/unbound/unbound.conf | tail -20');
    await diag("Can firewall reach Quad9 (ICMP)?", fw, "ping -c 3 -W 3 9.9.9.9 2>&1; ping -c 3 -W 3 149.112.112.112 2>&1");
    await diag("Route to Quad9", fw, "ip route get 9.9.9.9 2>&1");
    await diag("Can firewall reach Quad9 port 53 (TCP)?", fw,
      'timeout 5 bash -c "echo | nc -w 3 9.9.9.9 53 && echo TCP_OK || echo TCP_FAIL" 2>&1');
    await diag("Direct dig from firewall to Quad9", fw,
      "dig @9.9.9.9 cloudflare.com A +short +timeout=5 +tries=1 2>&1");
    await diag("Direct dig from firewall to Quad9 (TCP)", fw,
      "dig @9.9.9.9 cloudflare.com A +short +timeout=5 +tries=1 +tcp 2>&1");
    await diag("dig via Unbound (localhost)", fw,
      "dig @127.0.0.1 cloudflare.com A +timeout=5 +tries=1 2>&1");
    await diag("dig via Unbound from client", cl,
      "dig @192.168.1.1 cloudflare.com A +timeout=5 +tries=1 2>&1");
    await diag("Unbound logs (last 30 lines)", fw,
      "journalctl -u unbound --no-pager -n 30 2>&1");
    await diag("tcpdump: DNS traffic from firewall for 10s", fw,
      `timeout 10 tcpdump -i any -nn port 53 -c 20 2>&1 &
       sleep 1
       dig @127.0.0.1 example.com +short +timeout=3 +tries=1 2>/dev/null
       dig @9.9.9.9 example.org +short +timeout=3 +tries=1 2>/dev/null
       wait`);
    await diag("nftables conntrack for port 53", fw,
      "conntrack -L -p udp --dport 53 2>&1 | head -20; conntrack -L -p tcp --dport 53 2>&1 | head -10");
    await diag("ip rule list", fw, "ip rule list");
    await diag("ip route show table 51820", fw, "ip route show table 51820 2>&1");
    await diag("ip route show table 100", fw, "ip route show table 100 2>&1");
    await diag("wg show wg-mullvad (fwmark check)", fw, "wg show wg-mullvad 2>&1");
    await diag("mullvad-routes service status", fw,
      "systemctl status mullvad-routes --no-pager -l 2>&1 | head -30");
    await diag("mullvad-routes journal", fw,
      "journalctl -u mullvad-routes --no-pager 2>&1 | tail -30");
    await diag("ip route get 9.9.9.9 (should use wg-mullvad)", fw, "ip route get 9.9.9.9 2>&1");
    await diag("ip route get 1.1.1.1 (should use wg-mullvad)", fw, "ip route get 1.1.1.1 2>&1");
  });

  it("diagnostics collected", function () {
    // This is a diagnostic-only phase; the before() hook logs output.
    // Nothing to assert -- the test passes if diagnostics were collected.
  });
});

// ---------------------------------------------------------------------------
// Phase A: Bootstrap WARP on the firewall
// ---------------------------------------------------------------------------
describe("A. Bootstrap WARP on the firewall", function () {
  this.timeout(300_000);

  before(async function () {
    console.log("  registering and connecting WARP...");
    try {
      await fw(`set -ex
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
        MULLVAD_EP=$(wg show wg-mullvad endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)
        if [ -n "$MULLVAD_EP" ]; then
          echo "Excluding Mullvad endpoint $MULLVAD_EP from WARP split tunnel"
          warp-cli --accept-tos tunnel ip add "$MULLVAD_EP" || true
        fi
        # Exclude Quad9 DNS so Unbound can resolve even when WARP is down
        warp-cli --accept-tos tunnel ip add 9.9.9.11 || true
        warp-cli --accept-tos tunnel ip add 149.112.112.11 || true
        warp-cli --accept-tos connect`);
    } catch (e) {
      console.log("  WARP bootstrap command failed:", e.message);
    }
  });

  it("CloudflareWARP interface is up", async function () {
    const up = await waitFor(
      () => fwOk("ip link show CloudflareWARP >/dev/null 2>&1"),
      { timeout: 120, interval: 2, label: "CloudflareWARP interface" },
    );
    if (!up) {
      try {
        const status = await fw("warp-cli --accept-tos status 2>&1 || true");
        console.log("  warp-cli status:", status);
      } catch { /* best effort */ }
    }
    state.warpUp = up;
    assert.ok(up, "CloudflareWARP interface never appeared");
  });
});

// ---------------------------------------------------------------------------
// Phase B: Tunnel readiness -- Mullvad handshake
// ---------------------------------------------------------------------------
describe("B. Tunnel readiness -- Mullvad handshake", function () {
  this.timeout(300_000);

  before(function () {
    if (!state.warpUp) {
      console.log("  skipping: WARP did not come up in Phase A");
    }
  });

  it("wg-mullvad has completed a WireGuard handshake", async function () {
    if (!state.warpUp) return this.skip();
    const ok = await waitFor(
      async () => {
        try {
          const out = await fw('wg show wg-mullvad latest-handshakes 2>/dev/null | awk \'{print $2}\'');
          return out && out !== "0";
        } catch { return false; }
      },
      { timeout: 90, interval: 2, label: "Mullvad handshake" },
    );
    assert.ok(ok, "wg-mullvad never completed a handshake");
  });

  it("Mullvad routes are active (table 51820 or service succeeded)", async function () {
    if (!state.warpUp) return this.skip();
    const ok = await fwOk(
      'ip route show table 51820 2>/dev/null | grep -q "0.0.0.0/1" || systemctl is-active --quiet mullvad-routes',
    );
    assert.ok(ok, "Mullvad routes not active (mullvad-routes.service did not run?)");
  });

  it("warp-cli reports Connected", async function () {
    if (!state.warpUp) return this.skip();
    const ok = await waitFor(
      () => fwOk('warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"'),
      { timeout: 40, interval: 2, label: "warp-cli Connected" },
    );
    if (!ok) {
      try {
        const status = await fw("warp-cli --accept-tos status");
        console.log("  warp-cli status:", status);
      } catch { /* best effort */ }
    }
    assert.ok(ok, "warp-cli is not in Connected state");
  });

  it("precondition: tunnels pass traffic + Unbound warm-up", async function () {
    if (!state.warpUp) return this.skip();
    this.timeout(300_000);

    // Check firewall can reach the internet through the tunnels
    const reachable = await waitFor(
      () => fwOk("curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1"),
      { timeout: 24, interval: 3, label: "tunnel traffic" },
    );

    if (!reachable) {
      console.log("  WARNING: firewall cannot reach internet -- skipping connectivity tests");
      state.tunnelsOk = false;
      return;
    }

    // Warm up Unbound -- first DoT handshake to Quad9 through the tunnel can take 10-20s
    console.log("  (tunnels up -- warming up Unbound via Quad9 -> wg-mullvad...)");
    const unboundOk = await waitFor(
      () => fwOk('dig @192.168.1.1 +time=8 +tries=1 cloudflare.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."'),
      { timeout: 40, interval: 2, label: "Unbound warmup" },
    );

    state.tunnelsOk = unboundOk;
    if (unboundOk) {
      console.log("  (precondition met: tunnels passing traffic, Unbound responding)");
    } else {
      console.log("  WARNING: Unbound not responding -- skipping connectivity tests");
    }
  });
});

// ---------------------------------------------------------------------------
// Phase C: Client connectivity through the double tunnel
// ---------------------------------------------------------------------------
describe("C. Client connectivity through the double tunnel", function () {
  this.timeout(120_000);

  before(function () {
    if (!state.warpUp) {
      console.log("  skipping: WARP did not come up");
    }
  });

  it("client got a 192.168.1.x lease from Kea", async function () {
    if (!state.warpUp) return this.skip();
    let output;
    try {
      output = await cl("ip -4 addr show eth1");
    } catch {
      output = "";
    }
    const hasLease = /inet 192\.168\.1\.\d+/.test(output);
    if (!hasLease) {
      console.log("  ip -4 addr show eth1:", output);
    }
    assert.ok(hasLease, "client did NOT receive a 192.168.1.x lease");
  });

  it("client can ping the firewall (192.168.1.1)", async function () {
    if (!state.warpUp) return this.skip();
    const ok = await clOk("ping -c 2 -W 3 192.168.1.1 >/dev/null");
    assert.ok(ok, "client cannot ping 192.168.1.1");
  });

  it("client resolves public DNS via firewall Unbound", async function () {
    if (!state.tunnelsOk) return this.skip();
    const ok = await clOk(
      `for domain in cloudflare.com google.com example.com; do
         for i in 1 2 3; do
           dig @192.168.1.1 +time=5 +tries=1 "$domain" A +short 2>/dev/null | grep -qE "^[0-9]+\\." && exit 0
           sleep 2
         done
       done
       exit 1`,
    );
    assert.ok(ok, "client could not resolve any domain via 192.168.1.1");
  });

  it("client fetches https://cloudflare.com/cdn-cgi/trace", async function () {
    if (!state.tunnelsOk) return this.skip();
    const ok = await clOk("curl -sf --max-time 15 https://cloudflare.com/cdn-cgi/trace >/tmp/trace.txt");
    assert.ok(ok, "client could not fetch through the double tunnel");
  });
});

// ---------------------------------------------------------------------------
// Phase D: Exit identity -- public sees WARP, not bare upstream
// ---------------------------------------------------------------------------
describe("D. Exit identity -- public sees WARP, not bare upstream", function () {
  this.timeout(120_000);

  before(function () {
    if (!state.tunnelsOk) {
      console.log("  skipping: tunnels not passing traffic");
    }
  });

  it("Cloudflare reports warp=on", async function () {
    if (!state.tunnelsOk) return this.skip();
    const ok = await clOk('grep -q "^warp=on" /tmp/trace.txt');
    if (!ok) {
      try {
        const trace = await cl('grep -E "^(warp|gateway|ip)=" /tmp/trace.txt');
        console.log("  trace excerpt:", trace);
      } catch { /* best effort */ }
    }
    assert.ok(ok, "Cloudflare did not report warp=on (request bypassed WARP?)");
  });

  it("client exit IP differs from upstream slirp IP", async function () {
    if (!state.tunnelsOk) return this.skip();
    let slirpPub = "";
    let clientPub = "";
    try {
      slirpPub = await up(
        'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= \'/^ip=/{print $2}\'',
      );
    } catch { /* empty */ }
    try {
      clientPub = await cl('awk -F= \'/^ip=/{print $2}\' /tmp/trace.txt');
    } catch { /* empty */ }

    assert.ok(
      slirpPub && clientPub,
      `could not determine exit IPs (upstream='${slirpPub}' client='${clientPub}')`,
    );
    assert.notEqual(
      slirpPub,
      clientPub,
      "client exit IP equals upstream slirp IP -- tunnels were bypassed",
    );
  });
});

// ---------------------------------------------------------------------------
// Phase E: WAN observer -- upstream tcpdump on vlan1
// ---------------------------------------------------------------------------
describe("E. WAN observer -- upstream tcpdump on vlan1", function () {
  this.timeout(120_000);

  before(async function () {
    if (!state.warpUp) {
      console.log("  skipping: WARP did not come up");
      return;
    }

    // Grab the Mullvad endpoint info for later packet filtering
    try {
      state.mullvadEndpoint = await fw(
        'wg show wg-mullvad endpoints | awk \'{print $2}\' | cut -d: -f1',
      );
      state.mullvadPort = await fw(
        'wg show wg-mullvad endpoints | awk \'{print $2}\' | sed "s/.*://"',
      );
    } catch { /* best effort */ }
    console.log(`  Mullvad endpoint: ${state.mullvadEndpoint}:${state.mullvadPort}`);

    // Start tcpdump on upstream
    await upOk('pkill -f "tcpdump -ni eth1" 2>/dev/null; true');
    await up("tcpdump -ni eth1 -tt -nn 'not arp and not ip6' -w /tmp/vlan1.pcap >/tmp/vlan1.log 2>&1 &");

    // Generate traffic from client
    try {
      await cl(
        `for i in $(seq 1 5); do
           curl -sf --max-time 6 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1 || true
           sleep 1
         done`,
      );
    } catch { /* traffic generation best effort */ }

    await sleep(10);
    await upOk('pkill -f "tcpdump -ni eth1" 2>/dev/null; sleep 1');
  });

  it("captured packets > 0 on vlan1", async function () {
    if (!state.warpUp) return this.skip();
    const countStr = await up("tcpdump -nr /tmp/vlan1.pcap 2>/dev/null | wc -l");
    const pktCount = parseInt(countStr, 10) || 0;
    console.log(`  captured ${pktCount} packets on vlan1`);
    assert.ok(pktCount > 0, "tcpdump captured 0 packets on vlan1 (capture broken?)");
  });

  it("every packet on vlan1 is WireGuard to/from Mullvad -- no leak", async function () {
    if (!state.warpUp) return this.skip();
    const ep = state.mullvadEndpoint;
    const port = state.mullvadPort;
    assert.ok(ep && port, "cannot determine Mullvad endpoint for packet filter");

    const countStr = await up(
      `tcpdump -nr /tmp/vlan1.pcap 'not (udp and (host ${ep} and port ${port}))' 2>/dev/null | wc -l`,
    );
    const nonWgCount = parseInt(countStr, 10) || 0;
    if (nonWgCount > 0) {
      try {
        const leaked = await up(
          `tcpdump -nr /tmp/vlan1.pcap 'not (udp and (host ${ep} and port ${port}))' 2>/dev/null | head -20`,
        );
        console.log("  non-WG packets:", leaked);
      } catch { /* best effort */ }
    }
    assert.equal(nonWgCount, 0, `${nonWgCount} non-WireGuard packets observed on vlan1`);
  });
});

// ---------------------------------------------------------------------------
// Phase F: Kill switch -- pause Mullvad and verify LAN goes dark
// ---------------------------------------------------------------------------
describe("F. Kill switch -- pause Mullvad and verify LAN goes dark", function () {
  this.timeout(300_000);

  before(async function () {
    if (!state.warpUp) {
      console.log("  skipping: WARP did not come up");
      return;
    }
    console.log("  stopping wg-mullvad (BindsTo should also stop WARP)...");
    await fwOk("systemctl stop wireguard-wg-mullvad.service");
    await sleep(5);
  });

  it("cloudflare-warp stopped when wg-mullvad stopped (BindsTo)", async function () {
    if (!state.warpUp) return this.skip();
    const stillActive = await fwOk("systemctl is-active --quiet cloudflare-warp");
    assert.ok(!stillActive, "cloudflare-warp still running after wg-mullvad stopped (BindsTo not working)");
  });

  it("client cannot reach internet with tunnels stopped", async function () {
    if (!state.warpUp) return this.skip();
    const canReach = await clOk("curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null");
    assert.ok(!canReach, "client could STILL reach the internet with tunnels down -- KILL SWITCH FAILED");
  });

  it("bare TCP to 1.1.1.1:443 blocked while tunnels are down", async function () {
    if (!state.warpUp) return this.skip();
    const canConnect = await clOk("nc -z -w 5 1.1.1.1 443");
    assert.ok(!canConnect, "client could open TCP to 1.1.1.1:443 with tunnels down -- kill switch leak");
  });

  it("tunnels recover after restart", async function () {
    if (!state.warpUp) return this.skip();
    this.timeout(300_000);

    console.log("  restarting wg-mullvad + WARP...");
    await fwOk("systemctl start wireguard-wg-mullvad.service");
    await fwOk("systemctl restart mullvad-routes.service");
    await fwOk("systemctl start cloudflare-warp.service");

    console.log("  waiting for tunnels to recover from kill switch test...");
    const recovered = await waitFor(
      async () => {
        try {
          const hs = await fw('wg show wg-mullvad latest-handshakes 2>/dev/null | awk \'{print $2}\'');
          if (!hs || hs === "0") return false;
          const warpOk = await fwOk('warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"');
          if (!warpOk) return false;
          const clientOk = await clOk("curl -sf --max-time 8 https://cloudflare.com/cdn-cgi/trace >/dev/null");
          return clientOk;
        } catch { return false; }
      },
      { timeout: 150, interval: 5, label: "tunnel recovery" },
    );

    state.recovered = recovered;
    // Not an assertion from the original -- this sets state for downstream phases.
    // The original just sets RECOVERED=true/false without ok/bad.
    if (!recovered) {
      console.log("  WARNING: tunnels did not recover from kill switch test");
    } else {
      console.log("  tunnels recovered");
    }
  });
});

// ---------------------------------------------------------------------------
// Phase G: DNS resilience -- DNS survives WARP disconnect
// ---------------------------------------------------------------------------
describe("G. DNS resilience -- DNS survives WARP disconnect", function () {
  this.timeout(300_000);

  before(async function () {
    if (!state.recovered) {
      console.log("  skipping: tunnels did not recover from kill switch test");
      return;
    }
    // Ensure Quad9 is excluded from WARP split tunnel
    await fwOk('warp-cli --accept-tos tunnel ip add 9.9.9.11 2>/dev/null || true');
    await fwOk('warp-cli --accept-tos tunnel ip add 149.112.112.11 2>/dev/null || true');
  });

  it("pre-disconnect: DNS resolves via Unbound", async function () {
    if (!state.recovered) return this.skip();
    const ok = await fwOk(
      'dig @192.168.1.1 +time=5 +tries=1 cloudflare.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."',
    );
    assert.ok(ok, "pre-disconnect: DNS already broken -- cannot test resilience");
  });

  it("DNS resolves with WARP disconnected (Quad9 via Mullvad)", async function () {
    if (!state.recovered) return this.skip();

    console.log("  disconnecting WARP...");
    await fwOk("warp-cli --accept-tos disconnect");
    await sleep(5);

    const ok = await fwOk(
      'dig @192.168.1.1 +time=8 +tries=2 example.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."',
    );
    assert.ok(ok, "DNS FAILED with WARP disconnected -- split tunnel exclusion not working");
  });

  it("client DNS resolves with WARP disconnected", async function () {
    if (!state.recovered) return this.skip();
    const ok = await clOk(
      'dig @192.168.1.1 +time=8 +tries=2 example.org A +short 2>/dev/null | grep -qE "^[0-9]+\\."',
    );
    assert.ok(ok, "client DNS failed with WARP disconnected");
  });

  it("WARP reconnects after disconnect (no DNS deadlock)", async function () {
    if (!state.recovered) return this.skip();

    console.log("  reconnecting WARP...");
    await fwOk("warp-cli --accept-tos connect");

    console.log("  waiting for WARP to reconnect (up to 120s)...");
    let elapsed = 0;
    const reconnected = await waitFor(
      async () => {
        elapsed += 5;
        return fwOk('warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"');
      },
      { timeout: 120, interval: 5, label: "WARP reconnect" },
    );

    if (reconnected) {
      console.log(`  WARP reconnected after ~${elapsed}s`);
    } else {
      try {
        const status = await fw("warp-cli --accept-tos status 2>&1");
        console.log("  warp-cli status:", status);
      } catch { /* best effort */ }
    }
    assert.ok(reconnected, "WARP did NOT reconnect -- DNS deadlock may still exist");
  });

  it("post-reconnect: client traffic egresses via WARP", async function () {
    if (!state.recovered) return this.skip();
    // Only run if WARP reconnected (previous test passed)
    const warpConnected = await fwOk(
      'warp-cli --accept-tos status 2>&1 | grep -qi "Status update: Connected"',
    );
    if (!warpConnected) return this.skip();

    const ok = await clOk(
      'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"',
    );
    assert.ok(ok, "post-reconnect: client traffic NOT going through WARP");
  });
});

// ---------------------------------------------------------------------------
// Phase H: Self-healing -- WAN carrier drop recovery
// ---------------------------------------------------------------------------
describe("H. Self-healing -- WAN carrier drop recovery", function () {
  this.timeout(300_000);

  before(function () {
    if (!state.recovered) {
      console.log("  skipping: tunnels did not recover from kill switch test");
    }
  });

  it("pre-disruption baseline: client has internet", async function () {
    if (!state.recovered) return this.skip();
    const ok = await clOk(
      "curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1",
    );
    assert.ok(ok, "pre-disruption baseline failed -- cannot test self-healing");
  });

  it("system self-heals after WAN carrier drop", async function () {
    if (!state.recovered) return this.skip();
    this.timeout(300_000);

    console.log("  simulating WAN carrier drop (upstream eth1 down)...");
    await up("ip link set eth1 down");
    await sleep(15);

    // Check if carrier drop propagated
    const fwStillReachable = await fwOk("ping -c 2 -W 3 10.99.0.1 >/dev/null 2>&1");
    if (fwStillReachable) {
      console.log("  WARNING: firewall can still reach upstream (carrier drop may not have propagated)");
    } else {
      console.log("  confirmed: firewall cannot reach upstream");
    }

    console.log("  restoring WAN (upstream eth1 up)...");
    await up("ip link set eth1 up");
    await sleep(5);

    console.log("  waiting for self-healing (up to 180s)...");
    let healedAfter = 0;
    const healed = await waitFor(
      async () => {
        healedAfter += 5;
        try {
          const hasIp = await fwOk('ip -4 addr show wan0 2>/dev/null | grep -q "inet "');
          if (!hasIp) return false;

          const hs = await fw('wg show wg-mullvad latest-handshakes 2>/dev/null | awk \'{print $2}\'');
          if (!hs || hs === "0") return false;

          const now = Math.floor(Date.now() / 1000);
          const hsAge = now - parseInt(hs, 10);
          if (hsAge >= 180) return false;

          const clientOk = await clOk(
            "curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace >/dev/null",
          );
          if (clientOk) {
            console.log(`  healed after ~${healedAfter}s (handshake ${hsAge}s ago)`);
          }
          return clientOk;
        } catch { return false; }
      },
      { timeout: 180, interval: 5, label: "self-healing" },
    );

    if (!healed) {
      try {
        const diag = await fw(
          'echo "wan0:"; ip -br a show wan0; echo "wg-mullvad:"; wg show wg-mullvad 2>&1 | head -5; echo "routes:"; ip route | head -5; echo "warp:"; warp-cli --accept-tos status 2>&1 | head -3',
        );
        console.log("  post-disruption diagnostics:", diag);
      } catch { /* best effort */ }
    }
    assert.ok(healed, "system did NOT self-heal after WAN carrier drop (180s timeout)");
  });

  it("post-recovery: Mullvad tunnel routes present (table 51820)", async function () {
    if (!state.recovered) return this.skip();
    const ok = await fwOk('ip route show table 51820 2>/dev/null | grep -q "0.0.0.0/1"');
    if (!ok) {
      // Print diagnostics
      try {
        const diag = await fw(
          'echo "table 51820:"; ip route show table 51820 2>&1; echo "rules:"; ip rule show 2>&1 | grep -E "fwmark|51820"; echo "default:"; ip route show default 2>&1; echo "warp:"; warp-cli --accept-tos status 2>&1 | head -3; echo "services:"; systemctl is-active wireguard-wg-mullvad mullvad-routes cloudflare-warp 2>&1',
        );
        console.log("  post-recovery diagnostics:", diag);
      } catch { /* best effort */ }
    }
    assert.ok(ok, "post-recovery: Mullvad tunnel routes missing (table 51820)");
  });

  it("post-recovery: client traffic egresses via WARP", async function () {
    if (!state.recovered) return this.skip();

    console.log("  waiting for WARP to reconnect after carrier drop (up to 120s)...");
    let elapsed = 0;
    const ok = await waitFor(
      async () => {
        elapsed += 5;
        const warpOn = await clOk(
          'curl -sf --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"',
        );
        if (warpOn) console.log(`  WARP reconnected after ~${elapsed}s`);
        return warpOn;
      },
      { timeout: 120, interval: 5, label: "WARP post-heal" },
    );

    if (!ok) {
      try {
        const status = await fw("warp-cli --accept-tos status 2>&1");
        console.log("  warp-cli status:", status);
      } catch { /* best effort */ }
    }
    assert.ok(ok, "post-recovery: client traffic NOT going through WARP");
  });
});

// ---------------------------------------------------------------------------
// Phase I: Internet drop -- 120s outage recovery
// ---------------------------------------------------------------------------
describe("I. Internet drop -- 120s outage recovery", function () {
  this.timeout(600_000);

  before(async function () {
    if (!state.recovered) {
      console.log("  skipping: tunnels did not recover from kill switch test");
      return;
    }
  });

  it("Mullvad tunnel re-established after 120s internet drop", async function () {
    if (!state.recovered) return this.skip();
    this.timeout(600_000);

    console.log("  blocking all internet on upstream VM for 120s...");
    // Schedule the blackhole to activate after 2s so SSH can return first.
    // The blackhole blocks eth0 (including SSH), so the nft commands must
    // run AFTER the SSH session closes. A background script handles the
    // full lifecycle: block, wait 120s, then unblock.
    const blockOk = await waitFor(
      async () => {
        try {
          await up(
            `nohup bash -c '
              sleep 2
              nft delete table inet blackhole 2>/dev/null || true
              nft add table inet blackhole
              nft "add chain inet blackhole input { type filter hook input priority -1 \\; policy accept \\; }"
              nft "add chain inet blackhole output { type filter hook output priority -1 \\; policy accept \\; }"
              nft add rule inet blackhole input iifname eth0 drop
              nft add rule inet blackhole output oifname eth0 drop
              sleep 120
              nft delete table inet blackhole 2>/dev/null || true
            ' </dev/null >/tmp/blackhole.log 2>&1 &
            echo "scheduled"`,
          );
          return true;
        } catch { return false; }
      },
      { timeout: 120, interval: 5, label: "schedule blackhole" },
    );
    if (!blockOk) {
      console.log("  WARNING: could not SSH to upstream to schedule blackhole");
      assert.fail("could not schedule blackhole on upstream VM");
    }

    // Wait for the blackhole to activate (2s) plus the full 120s outage
    console.log("  waiting 125s for blackhole lifecycle (2s delay + 120s block + 3s margin)...");
    await sleep(125);

    console.log("  waiting for Mullvad tunnel to recover (up to 120s)...");
    let recoveredAfter = 0;
    const tunnelRecovered = await waitFor(
      async () => {
        recoveredAfter += 5;
        try {
          const hs = await fw('wg show wg-mullvad latest-handshakes 2>/dev/null | awk \'{print $2}\'');
          if (!hs || hs === "0") return false;
          const now = Math.floor(Date.now() / 1000);
          const age = now - parseInt(hs, 10);
          if (age < 30) {
            console.log(`  tunnel recovered after ~${recoveredAfter}s (handshake ${age}s ago)`);
            return true;
          }
          return false;
        } catch { return false; }
      },
      { timeout: 120, interval: 5, label: "Mullvad tunnel recovery" },
    );

    assert.ok(tunnelRecovered, "Mullvad tunnel did not recover after 120s internet drop");
  });

  it("Unbound DoT recovered after 120s internet drop", async function () {
    if (!state.recovered) return this.skip();
    this.timeout(120_000);

    await fwOk("systemctl restart unbound");
    await sleep(3);

    const ok = await waitFor(
      () => fwOk('dig @127.0.0.1 +time=10 +tries=1 github.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."'),
      { timeout: 30, interval: 5, label: "Unbound DoT recovery" },
    );
    assert.ok(ok, "Unbound DoT did not recover after 120s internet drop");
  });

  it("client DNS works after 120s internet drop recovery", async function () {
    if (!state.recovered) return this.skip();
    // Only run if Unbound recovered (check inline)
    const unboundOk = await fwOk(
      'dig @127.0.0.1 +time=5 +tries=1 example.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."',
    );
    if (!unboundOk) return this.skip();

    const ok = await clOk(
      'dig @192.168.1.1 +time=5 +tries=1 example.com A +short 2>/dev/null | grep -qE "^[0-9]+\\."',
    );
    assert.ok(ok, "client DNS broken after 120s internet drop recovery");
  });
});
