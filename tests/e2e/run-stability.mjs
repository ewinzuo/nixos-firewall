#!/usr/bin/env node
// Run the e2e test suite N times and report stability.
// Usage: node tests/e2e/run-stability.mjs [N]  (default: 10)

import { $, which } from "zx";
import { execSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rm, mkdir } from "node:fs/promises";

$.verbose = true;

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNTIME = resolve(HERE, ".runtime");
const N = parseInt(process.argv[2] || "10", 10);

let passed = 0;
let failed = 0;
const errors = [];

await mkdir(RUNTIME, { recursive: true });

function cleanupBetweenRuns() {
  for (const vmName of ["e2e-firewall", "e2e-client", "e2e-upstream"]) {
    try {
      const pids = execSync(`pgrep -f "\\\\-name ${vmName}"`, { encoding: "utf8" }).trim();
      if (pids) {
        for (const pid of pids.split("\n")) {
          try { process.kill(parseInt(pid, 10), "SIGKILL"); } catch { /* */ }
        }
      }
    } catch { /* no matching processes */ }
  }

  try {
    execSync(`rm -f "${RUNTIME}/mullvad.json"`, { stdio: "ignore" });
    execSync(`find "${RUNTIME}" -name '*.qcow2' -delete`, { stdio: "ignore" });
  } catch { /* */ }

  // Wait for ports to be released
  for (let i = 0; i < 20; i++) {
    try {
      const ss = execSync("ss -tlnp 2>/dev/null", { encoding: "utf8" });
      if (!ss.match(/:(2223|2224)\b/)) return;
    } catch {
      return;
    }
    execSync("sleep 1");
  }
  console.error("WARNING: ports 2223/2224 still in use after 20s");
}

for (let run = 1; run <= N; run++) {
  console.log(`══════ RUN ${run}/${N} ══════`);
  cleanupBetweenRuns();

  try {
    await $({
      env: {
        ...process.env,
        SSH_ASKPASS_REQUIRE: "never",
        DISPLAY: "",
        E2E_NO_BELL: "1",
        E2E_REPORT_FILE: resolve(RUNTIME, `report-${run}.xml`),
      },
    })`node ${resolve(HERE, "run-e2e.mjs")}`;
    passed++;
    console.log(`>> RUN ${run}: PASSED`);
  } catch (err) {
    failed++;
    errors.push(`run ${run}`);
    console.log(`>> RUN ${run}: FAILED (rc=${err.exitCode ?? 1})`);
  }
  console.log();
}

console.log("══════════════════════════════════════════════════════");
console.log(`STABILITY: ${passed}/${N} passed, ${failed}/${N} failed`);
if (failed > 0) {
  console.log(`Failed runs: ${errors.join(", ")}`);
}
console.log("══════════════════════════════════════════════════════");

process.exit(failed > 0 ? 1 : 0);
