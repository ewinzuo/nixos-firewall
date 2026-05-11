#!/usr/bin/env bash
# Run the e2e test suite N times and report stability.
# Usage: tests/e2e/run-stability.sh [N]  (default: 10)
set -uo pipefail

N="${1:-10}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$HERE/.runtime"
PASSED=0
FAILED=0
ERRORS=()

mkdir -p "$RUNTIME"

cleanup_between_runs() {
  # Kill any orphaned QEMU VMs by matching the e2e VM names.
  # We match specific VM names instead of "qemu-system" to avoid
  # killing the shell running this script (pkill -f footgun).
  for vm_name in e2e-firewall e2e-client e2e-upstream; do
    pgrep -f "\\-name $vm_name" | xargs -r kill -9 2>/dev/null || true
  done

  # Clean disk images and decrypted secrets
  rm -f "$RUNTIME/mullvad.json"
  find "$RUNTIME" -name '*.qcow2' -delete 2>/dev/null || true

  # Wait for ports to actually be released
  for i in $(seq 1 20); do
    ss -tlnp 2>/dev/null | grep -qE ':(2223|2224)' || return 0
    sleep 1
  done
  echo "WARNING: ports 2223/2224 still in use after 20s" >&2
}

for run in $(seq 1 "$N"); do
  echo "══════ RUN $run/$N ══════"
  cleanup_between_runs

  # Run the test
  SSH_ASKPASS_REQUIRE=never DISPLAY= E2E_NO_BELL=1 \
    E2E_REPORT_FILE="$RUNTIME/report-$run.xml" \
    "$HERE/run-e2e.sh" 2>&1
  rc=$?

  if (( rc == 0 )); then
    PASSED=$((PASSED+1))
    echo ">> RUN $run: PASSED"
  else
    FAILED=$((FAILED+1))
    ERRORS+=("run $run")
    echo ">> RUN $run: FAILED (rc=$rc)"
  fi
  echo
done

echo "══════════════════════════════════════════════════════"
echo "STABILITY: $PASSED/$N passed, $FAILED/$N failed"
if (( FAILED > 0 )); then
  echo "Failed runs: ${ERRORS[*]}"
fi
echo "══════════════════════════════════════════════════════"

exit $(( FAILED > 0 ? 1 : 0 ))
