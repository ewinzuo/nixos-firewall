#!/usr/bin/env node
// Black-box end-to-end test orchestrator for the double-VPN tunnel firewall.
//
// Brings up three QEMU VMs wired together with socket-mcast vlans:
//
//               ┌──────────────┐ vlan2  ┌──────────────┐ vlan1  ┌──────────────┐
//               │   client     │────────│   firewall   │────────│   upstream   │
//               │ (LAN host)   │  (LAN) │  (br-lan +   │  (WAN) │ (NAT gateway │
//               │              │        │   wan0 +     │        │  + observer) │
//               │              │        │  WARP +      │        │              │
//               │              │        │  Mullvad)    │        │              │
//               └──────────────┘        └──────────────┘        └──────────────┘
//                     │                       │                       │
//                     └─ slirp:2223           └─ slirp:2222           └─ slirp:2224
//                        (mgmt SSH)              (mgmt SSH)              (mgmt SSH +
//                                                                        real internet
//                                                                        for NAT'd VMs)
//
// Usage: node tests/e2e/run-e2e.mjs
//        npm run e2e             (via package.json)
//
// Requires: nix, sops, age, qemu-system-x86_64, ssh, ssh-keygen
//
// CI/CD:
//   Exit code 0 = all pass, 1 = failures
//   JUnit XML report: tests/e2e/.runtime/report.xml
//   Set E2E_REPORT_FILE to override report location
//   Set E2E_NO_BELL=1 to suppress desktop notification

import { $, cd, which } from "zx";
import { spawn, execSync } from "node:child_process";
import { mkdir, chmod, access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

$.verbose = true;

// ── Paths ──────────────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../..");
const RUNTIME = resolve(HERE, ".runtime");
const LOGS = resolve(RUNTIME, "logs");
const SECRETS_ENC = resolve(HERE, "secrets/mullvad.yaml");
const SECRETS_DEC = resolve(RUNTIME, "mullvad.json");
const RUNNER_KEY = resolve(RUNTIME, "runner-key");
const RUNNER_KEY_PUB = `${RUNNER_KEY}.pub`;
const REPORT_FILE = process.env.E2E_REPORT_FILE || resolve(RUNTIME, "report.xml");

const runStart = Date.now();

// ── VM working dirs ────────────────────────────────────────────────────
const FW_DIR = resolve(RUNTIME, "fw");
const CL_DIR = resolve(RUNTIME, "cl");
const UP_DIR = resolve(RUNTIME, "up");

await mkdir(RUNTIME, { recursive: true });
await mkdir(LOGS, { recursive: true });
await mkdir(FW_DIR, { recursive: true });
await mkdir(CL_DIR, { recursive: true });
await mkdir(UP_DIR, { recursive: true });

// ── Cleanup on exit ────────────────────────────────────────────────────
/** @type {import("node:child_process").ChildProcess[]} */
const vmProcs = [];
let cleanupRan = false;

async function cleanup() {
  if (cleanupRan) return;
  cleanupRan = true;

  console.log("── cleanup ────────────────────────────────────────────────────");

  // TERM all VM processes
  for (const proc of vmProcs) {
    try {
      process.kill(-proc.pid, "SIGTERM"); // kill entire process group
    } catch {
      // already dead
    }
  }

  // Wait 2s then KILL survivors
  await new Promise((r) => setTimeout(r, 2000));
  for (const proc of vmProcs) {
    try {
      process.kill(-proc.pid, "SIGKILL");
    } catch {
      // already dead
    }
  }

  // Wait for ports 2223/2224 to be released (up to 10s)
  for (let i = 0; i < 10; i++) {
    try {
      const ss = execSync("ss -tlnp 2>/dev/null", { encoding: "utf8" });
      if (!ss.match(/:(2223|2224)\b/)) break;
    } catch {
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

// Register cleanup for all exit paths
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, async () => {
    await cleanup();
    process.exit(128 + { SIGINT: 2, SIGTERM: 15, SIGHUP: 1 }[sig]);
  });
}
process.on("exit", () => {
  // Synchronous last-resort cleanup (the async version should have run already)
  if (!cleanupRan) {
    cleanupRan = true;
    for (const proc of vmProcs) {
      try { process.kill(-proc.pid, "SIGKILL"); } catch { /* */ }
    }
  }
});

// ── Sanity: required tools ─────────────────────────────────────────────
const requiredTools = ["nix", "sops", "qemu-system-x86_64", "ssh", "ssh-keygen"];
for (const bin of requiredTools) {
  if (!which.sync(bin, { nothrow: true })) {
    console.error(`ERROR: required tool '${bin}' not found in PATH.`);
    console.error("Hint: nix shell nixpkgs#sops nixpkgs#age nixpkgs#qemu nixpkgs#openssh");
    process.exit(1);
  }
}

// ── Ensure a runner SSH keypair exists ──────────────────────────────────
try {
  await access(RUNNER_KEY, constants.F_OK);
} catch {
  await $`ssh-keygen -t ed25519 -N ${""} -C e2e-runner -f ${RUNNER_KEY}`;
}
await chmod(RUNNER_KEY, 0o600);
process.env.E2E_SSH_PUBKEY_FILE = RUNNER_KEY_PUB;

// ── 1. Decrypt Mullvad secrets ─────────────────────────────────────────
try {
  await access(SECRETS_ENC, constants.F_OK);
} catch {
  console.error(`ERROR: ${SECRETS_ENC} not found.`);
  console.error("Create it from tests/e2e/secrets/mullvad.example.yaml and encrypt with sops.");
  process.exit(1);
}

console.log("── decrypting Mullvad secrets ─────────────────────────────────");
await $`sops --decrypt --output-type json --output ${SECRETS_DEC} ${SECRETS_ENC}`;
await chmod(SECRETS_DEC, 0o600);
process.env.E2E_MULLVAD_JSON = SECRETS_DEC;

// ── 2. Build the three VMs ─────────────────────────────────────────────
console.log("── building VMs (this may take a while on first run) ──────────");
await $`nix build -L --impure ${REPO}#e2e-firewall-vm ${REPO}#e2e-client-vm ${REPO}#e2e-upstream-vm --out-link ${RUNTIME}/result-fw`;

// Resolve each store path explicitly
const fwVmPath = (await $`nix build --impure ${REPO}#e2e-firewall-vm --no-link --print-out-paths`).stdout.trim();
const clVmPath = (await $`nix build --impure ${REPO}#e2e-client-vm --no-link --print-out-paths`).stdout.trim();
const upVmPath = (await $`nix build --impure ${REPO}#e2e-upstream-vm --no-link --print-out-paths`).stdout.trim();

const FW_VM = `${fwVmPath}/bin/run-e2e-firewall-vm`;
const CL_VM = `${clVmPath}/bin/run-e2e-client-vm`;
const UP_VM = `${upVmPath}/bin/run-e2e-upstream-vm`;

for (const [name, vm] of [["firewall", FW_VM], ["client", CL_VM], ["upstream", UP_VM]]) {
  try {
    await access(vm, constants.X_OK);
  } catch {
    console.error(`ERROR: built VM script missing/not executable: ${vm}`);
    process.exit(1);
  }
}

// ── 3. Launch the VMs ──────────────────────────────────────────────────
// Socket-mcast vlans (virtual L2 segments):
//   vlan1 = firewall.wan0 <-> upstream.eth1   (multicast 230.0.0.1:5559)
//   vlan2 = firewall.lan1 <-> client.eth1     (multicast 230.0.0.1:5560)

const VLAN1_MCAST = "230.0.0.1:5559";
const VLAN2_MCAST = "230.0.0.1:5560";

// Stable MACs per (vm, nic) so the firewall leases stay consistent.
const FW_MAC_WAN = "52:54:00:11:00:01";
const FW_MAC_LAN = "52:54:00:11:00:02";
const CL_MAC_LAN = "52:54:00:22:00:01";
const UP_MAC_WAN = "52:54:00:33:00:01";

const LOCAL = "localaddr=127.0.0.1";

// QEMU_OPTS per VM
const FW_OPTS = [
  `-netdev socket,id=netvlan1,mcast=${VLAN1_MCAST},${LOCAL}`,
  `-device virtio-net-pci,netdev=netvlan1,mac=${FW_MAC_WAN}`,
  `-netdev socket,id=netvlan2,mcast=${VLAN2_MCAST},${LOCAL}`,
  `-device virtio-net-pci,netdev=netvlan2,mac=${FW_MAC_LAN}`,
].join(" ");

const CL_OPTS = [
  `-netdev socket,id=netvlan2,mcast=${VLAN2_MCAST},${LOCAL}`,
  `-device virtio-net-pci,netdev=netvlan2,mac=${CL_MAC_LAN}`,
].join(" ");

const UP_OPTS = [
  `-netdev socket,id=netvlan1,mcast=${VLAN1_MCAST},${LOCAL}`,
  `-device virtio-net-pci,netdev=netvlan1,mac=${UP_MAC_WAN}`,
].join(" ");

/**
 * Launch a VM as a background process in its own session.
 * @param {string} name    - Human label (upstream, firewall, client)
 * @param {string} script  - Path to the run-e2e-*-vm script
 * @param {string} workdir - Working directory (isolates NIX_DISK_IMAGE)
 * @param {string} opts    - Extra QEMU_OPTS
 * @param {string} logfile - Where to send stdout+stderr
 */
function startVm(name, script, workdir, opts, logfile) {
  console.log(`── starting ${name} ─────────────────────────────────────────────`);

  // detached:true makes Node call setsid() after fork, so the bash we
  // spawn is itself the session/pgroup leader and proc.pid IS that pgid.
  // (Wrapping with external `setsid bash ...` doesn't work: setsid forks
  // and the parent — whose pid Node returns — exits. The real pgid then
  // belongs to a process we have no handle on, and kill(-proc.pid) gives
  // ESRCH, silently leaking the QEMU.)
  const proc = spawn(
    "bash",
    [
      "-c",
      `cd "${workdir}" && QEMU_OPTS="${opts}" QEMU_KERNEL_PARAMS="console=ttyS0,115200" "${script}" -nographic >"${logfile}" 2>&1`,
    ],
    {
      detached: true,
      stdio: "ignore",
      env: { ...process.env },
    },
  );

  vmProcs.push(proc);
  console.log(`${name} pid=${proc.pid} log=${logfile}`);
  return proc;
}

startVm("upstream", UP_VM, UP_DIR, UP_OPTS, `${LOGS}/upstream.log`);
startVm("firewall", FW_VM, FW_DIR, FW_OPTS, `${LOGS}/firewall.log`);
startVm("client", CL_VM, CL_DIR, CL_OPTS, `${LOGS}/client.log`);

// ── 4. Wait for SSH on each VM ──────────────────────────────────────────
const SSH_OPTS = [
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "ConnectTimeout=3",
  "-o", "LogLevel=ERROR",
  "-o", "IdentitiesOnly=yes",
  "-i", RUNNER_KEY,
];

const FW_JUMP_PROXY = [
  "ssh", ...SSH_OPTS, "-p", "2223", "-W", "%h:%p", "root@127.0.0.1",
].join(" ");

/**
 * Try to SSH to a VM and run `true`. Returns true on success.
 */
async function trySsh(port) {
  try {
    await $({ quiet: true })`ssh ${SSH_OPTS} -p ${port} root@127.0.0.1 true`;
    return true;
  } catch {
    return false;
  }
}

/**
 * Try to SSH to the firewall via the client jump host.
 */
async function trySshFirewall() {
  try {
    await $({ quiet: true })`ssh ${SSH_OPTS} -o ${`ProxyCommand=${FW_JUMP_PROXY}`} root@192.168.1.1 true`;
    return true;
  } catch {
    return false;
  }
}

/**
 * Poll SSH until reachable or timeout (180s).
 */
async function waitForSsh(name, probeFn, timeoutSec = 180, intervalSec = 2) {
  console.log(`── waiting for ${name} SSH ────────────────────────────────────`);
  const deadline = Date.now() + timeoutSec * 1000;
  while (Date.now() < deadline) {
    if (await probeFn()) {
      console.log(`${name} reachable.`);
      return;
    }
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
  console.error(`ERROR: ${name} did not become SSH-reachable in time.`);
  try {
    const logName = name.replace(/ .*/,""); // "firewall via client jump" -> "firewall"
    const log = await readFile(`${LOGS}/${logName}.log`, "utf8");
    const lines = log.split("\n");
    console.error("─── last 60 lines of log: ───");
    console.error(lines.slice(-60).join("\n"));
  } catch { /* log might not exist */ }
  await cleanup();
  process.exit(1);
}

await waitForSsh("upstream", () => trySsh(2224));
await waitForSsh("client", () => trySsh(2223));
await waitForSsh("firewall via client jump", () => trySshFirewall(), 180, 5);

// ── 5. Run the mocha test suite ─────────────────────────────────────────
console.log("── running assertions ─────────────────────────────────────────");

cd(HERE);

let testExitCode;
try {
  await $({
    env: {
      ...process.env,
      RUNNER_KEY,
      E2E_REPORT_FILE: REPORT_FILE,
    },
  })`npx mocha e2e.test.mjs`;
  testExitCode = 0;
} catch (err) {
  testExitCode = err.exitCode ?? 1;
}

const totalTimeSec = Math.round((Date.now() - runStart) / 1000);

if (testExitCode === 0) {
  console.log(`── e2e PASS (${totalTimeSec}s total) ─────────────────────────────`);
} else {
  console.error(`── e2e FAIL (rc=${testExitCode}, ${totalTimeSec}s total) ────────────────────`);
  console.error(`VM logs: ${LOGS}`);
  console.error(`Report:  ${REPORT_FILE}`);
}

// ── Desktop notification (doorbell) ────────────────────────────────────
if (process.env.E2E_NO_BELL !== "1") {
  const summary = testExitCode === 0
    ? `E2E PASS (${totalTimeSec}s)`
    : `E2E FAIL (${totalTimeSec}s)`;

  if (which.sync("notify-send", { nothrow: true })) {
    try {
      await $({ quiet: true })`notify-send -u normal "nixos-firewall e2e" ${summary}`;
    } catch { /* best-effort */ }
  }
  process.stdout.write("\x07"); // terminal bell
}

// ── Cleanup and exit ───────────────────────────────────────────────────
await cleanup();
process.exit(testExitCode);
