#!/usr/bin/env bash
# Black-box end-to-end test for the double-VPN tunnel firewall.
#
# Brings up three QEMU VMs wired together with socket-mcast vlans:
#
#                 ┌──────────────┐ vlan2  ┌──────────────┐ vlan1  ┌──────────────┐
#                 │   client     │────────│   firewall   │────────│   upstream   │
#                 │ (LAN host)   │  (LAN) │  (br-lan +   │  (WAN) │ (NAT gateway │
#                 │              │        │   wan0 +     │        │  + observer) │
#                 │              │        │  WARP +      │        │              │
#                 │              │        │  Mullvad)    │        │              │
#                 └──────────────┘        └──────────────┘        └──────────────┘
#                       │                       │                       │
#                       └─ slirp:2223           └─ slirp:2222           └─ slirp:2224
#                          (mgmt SSH)              (mgmt SSH)              (mgmt SSH +
#                                                                          real internet
#                                                                          for NAT'd VMs)
#
# Once everything's up, the assertion driver (tests/e2e/test-driver.sh) is
# executed via SSH and proves:
#   - both tunnels handshake (wg-mullvad + CloudflareWARP)
#   - public exit IP is NOT the upstream's slirp IP — it's a Cloudflare egress
#   - upstream tcpdump on vlan1 shows ONLY UDP/51820 leaving the firewall
#   - kill switch drops bare WAN traffic when the tunnels are paused
#
# Usage: tests/e2e/run-e2e.sh
#
# Requires: nix, sops, age, qemu-system-x86_64, ssh, sshpass

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUNTIME="$HERE/.runtime"
LOGS="$RUNTIME/logs"
SECRETS_ENC="$HERE/secrets/mullvad.yaml"
SECRETS_DEC="$RUNTIME/mullvad.json"
RUNNER_KEY="$RUNTIME/runner-key"
RUNNER_KEY_PUB="$RUNNER_KEY.pub"
DRIVER="$HERE/test-driver.sh"

mkdir -p "$RUNTIME" "$LOGS"

# ── Ensure a runner SSH keypair exists ────────────────────────────────
# This keypair is ephemeral (gitignored under .runtime/) and is used to
# log into all three test VMs as root. The public half is baked into
# each VM's authorized_keys at build time via E2E_SSH_PUBKEY_FILE.
if [[ ! -f "$RUNNER_KEY" ]]; then
  ssh-keygen -t ed25519 -N '' -C 'e2e-runner' -f "$RUNNER_KEY" >/dev/null
fi
chmod 600 "$RUNNER_KEY"
export E2E_SSH_PUBKEY_FILE="$RUNNER_KEY_PUB"

# Each VM gets its own working dir so the qemu-vm.nix script's transient
# disk image (NIX_DISK_IMAGE) doesn't collide with siblings.
FW_DIR="$RUNTIME/fw"
CL_DIR="$RUNTIME/cl"
UP_DIR="$RUNTIME/up"
mkdir -p "$FW_DIR" "$CL_DIR" "$UP_DIR"

# ── Cleanup on exit ────────────────────────────────────────────────────
PIDS=()
cleanup() {
  local rc=$?
  echo "── cleanup ────────────────────────────────────────────────────"
  for p in "${PIDS[@]:-}"; do
    if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
      kill -TERM "$p" 2>/dev/null || true
    fi
  done
  # Give them a beat to exit cleanly, then SIGKILL stragglers.
  sleep 2
  for p in "${PIDS[@]:-}"; do
    if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
      kill -KILL "$p" 2>/dev/null || true
    fi
  done
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ── Sanity: required tools ─────────────────────────────────────────────
for bin in nix sops qemu-system-x86_64 ssh ssh-keygen; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: required tool '$bin' not found in PATH." >&2
    echo "Hint: nix shell nixpkgs#sops nixpkgs#age nixpkgs#qemu nixpkgs#openssh" >&2
    exit 1
  fi
done

# ── 1. Decrypt Mullvad secrets ─────────────────────────────────────────
if [[ ! -f "$SECRETS_ENC" ]]; then
  echo "ERROR: $SECRETS_ENC not found." >&2
  echo "Create it from tests/e2e/secrets/mullvad.example.yaml and encrypt with sops." >&2
  exit 1
fi
echo "── decrypting Mullvad secrets ─────────────────────────────────"
sops --decrypt --output-type json "$SECRETS_ENC" > "$SECRETS_DEC"
chmod 600 "$SECRETS_DEC"

# Nix flakes only see git-tracked files, so .runtime/mullvad.json is
# invisible to flake evaluation. firewall-vm.nix reads the path from this
# env var via builtins.getEnv (requires --impure on nix build).
export E2E_MULLVAD_JSON="$SECRETS_DEC"

# ── 2. Build the three VMs ─────────────────────────────────────────────
echo "── building VMs (this may take a while on first run) ──────────"
nix build -L --impure \
  "$REPO#e2e-firewall-vm" \
  "$REPO#e2e-client-vm" \
  "$REPO#e2e-upstream-vm" \
  --out-link "$RUNTIME/result-fw" \
  --print-out-paths >/dev/null

# nix build with multiple installables only writes one --out-link, so
# resolve each store path explicitly via --print-out-paths.
FW_VM_PATH="$(nix build --impure "$REPO#e2e-firewall-vm" --no-link --print-out-paths)"
CL_VM_PATH="$(nix build --impure "$REPO#e2e-client-vm"   --no-link --print-out-paths)"
UP_VM_PATH="$(nix build --impure "$REPO#e2e-upstream-vm" --no-link --print-out-paths)"

FW_VM="$FW_VM_PATH/bin/run-e2e-firewall-vm"
CL_VM="$CL_VM_PATH/bin/run-e2e-client-vm"
UP_VM="$UP_VM_PATH/bin/run-e2e-upstream-vm"

for vm in "$FW_VM" "$CL_VM" "$UP_VM"; do
  if [[ ! -x "$vm" ]]; then
    echo "ERROR: built VM script missing/not executable: $vm" >&2
    exit 1
  fi
done

# ── 3. Launch the VMs ──────────────────────────────────────────────────
# Socket-mcast vlans (virtual L2 segments):
#   vlan1 = firewall.wan0 ↔ upstream.eth1   (multicast 230.0.0.1:5559)
#   vlan2 = firewall.lan1 ↔ client.eth1     (multicast 230.0.0.1:5560)
#
# qemu-vm.nix already creates the default user-mode eth0 (with the
# hostfwd we set in each VM's `virtualisation.forwardPorts`); we append
# additional socket-NICs via QEMU_OPTS.

VLAN1_MCAST="230.0.0.1:5559"
VLAN2_MCAST="230.0.0.1:5560"

# MACs are stable per (vm,nic) so the firewall's leases stay consistent
# across re-runs (Kea otherwise hands out a different IP each boot).
FW_MAC_WAN="52:54:00:11:00:01"
FW_MAC_LAN="52:54:00:11:00:02"
CL_MAC_LAN="52:54:00:22:00:01"
UP_MAC_WAN="52:54:00:33:00:01"

start_vm() {
  local name="$1" script="$2" workdir="$3" extra_opts="$4" logfile="$5"
  echo "── starting $name ─────────────────────────────────────────────"
  (
    cd "$workdir"
    QEMU_OPTS="$extra_opts" \
    QEMU_KERNEL_PARAMS="console=ttyS0,115200" \
      "$script" -nographic >"$logfile" 2>&1
  ) &
  local pid=$!
  PIDS+=("$pid")
  echo "$name pid=$pid log=$logfile"
}

# localaddr=127.0.0.1 forces QEMU socket-mcast to bind to loopback so
# multicast frames stay on-host instead of leaking out the default route
# (e.g. the WiFi interface). Without this, VMs can't see each other.
LOCAL="localaddr=127.0.0.1"

# Firewall: vlan1 (wan0) + vlan2 (lan1)
FW_OPTS="-netdev socket,id=netvlan1,mcast=$VLAN1_MCAST,$LOCAL -device virtio-net-pci,netdev=netvlan1,mac=$FW_MAC_WAN"
FW_OPTS="$FW_OPTS -netdev socket,id=netvlan2,mcast=$VLAN2_MCAST,$LOCAL -device virtio-net-pci,netdev=netvlan2,mac=$FW_MAC_LAN"

# Client: vlan2 only
CL_OPTS="-netdev socket,id=netvlan2,mcast=$VLAN2_MCAST,$LOCAL -device virtio-net-pci,netdev=netvlan2,mac=$CL_MAC_LAN"

# Upstream: vlan1 only (its eth0 slirp is already created by qemu-vm.nix
# and IS the path to the real internet for the NAT'd firewall traffic).
UP_OPTS="-netdev socket,id=netvlan1,mcast=$VLAN1_MCAST,$LOCAL -device virtio-net-pci,netdev=netvlan1,mac=$UP_MAC_WAN"

start_vm "upstream" "$UP_VM" "$UP_DIR" "$UP_OPTS" "$LOGS/upstream.log"
start_vm "firewall" "$FW_VM" "$FW_DIR" "$FW_OPTS" "$LOGS/firewall.log"
start_vm "client"   "$CL_VM" "$CL_DIR" "$CL_OPTS" "$LOGS/client.log"

# ── 4. Wait for SSH on each VM ────────────────────────────────────────
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=3 -o LogLevel=ERROR
          -o IdentitiesOnly=yes -i "$RUNNER_KEY")

# ProxyCommand for reaching the firewall through the client jump host.
# We can't use `-J` because OpenSSH does NOT propagate `-o` flags from
# the outer ssh to the inner ProxyJump child, so the inner connection
# would re-prompt for host-key verification (and on a desktop session
# spawn a graphical ssh-askpass dialog). Spelling it out as
# ProxyCommand applies all SSH_OPTS to the jump connection too.
FW_JUMP_PROXY="ssh ${SSH_OPTS[*]} -p 2223 -W %h:%p root@127.0.0.1"

ssh_to() {
  local port="$1"; shift
  ssh "${SSH_OPTS[@]}" -p "$port" root@127.0.0.1 "$@"
}

wait_for_ssh() {
  local name="$1" port="$2"
  local deadline=$(( $(date +%s) + 600 ))   # 10 min: WARP can be slow on cold boot
  echo "── waiting for $name SSH on host:$port ────────────────────────"
  while (( $(date +%s) < deadline )); do
    if ssh_to "$port" true 2>/dev/null; then
      echo "$name reachable."
      return 0
    fi
    sleep 5
  done
  echo "ERROR: $name did not become SSH-reachable in time." >&2
  echo "─── last 60 lines of log: ───" >&2
  tail -n 60 "$LOGS/${name}.log" >&2 || true
  return 1
}

wait_for_ssh upstream 2224
wait_for_ssh client   2223

# Firewall SSH goes via the client VM as a jump host (client is on br-lan,
# which nftables permits for SSH). This avoids needing an eth0/mgmt port-
# forward on the firewall and tests the real LAN path.
echo "── waiting for firewall SSH via client jump ────────────────────"
fw_deadline=$(( $(date +%s) + 600 ))
while (( $(date +%s) < fw_deadline )); do
  if ssh "${SSH_OPTS[@]}" -o "ProxyCommand=$FW_JUMP_PROXY" root@192.168.1.1 true 2>/dev/null; then
    echo "firewall reachable via client."
    break
  fi
  sleep 5
done
if (( $(date +%s) >= fw_deadline )); then
  echo "ERROR: firewall not SSH-reachable via client jump in time." >&2
  tail -n 60 "$LOGS/firewall.log" >&2 || true
  exit 1
fi

# ── 5. Hand off to the test driver ────────────────────────────────────
if [[ ! -x "$DRIVER" ]]; then
  echo "ERROR: test driver not executable: $DRIVER" >&2
  exit 1
fi

echo "── running assertions ─────────────────────────────────────────"
RUNNER_KEY="$RUNNER_KEY" "$DRIVER"
RC=$?

if (( RC == 0 )); then
  echo "── e2e PASS ───────────────────────────────────────────────────"
else
  echo "── e2e FAIL (rc=$RC) ──────────────────────────────────────────" >&2
  echo "VM logs are in $LOGS" >&2
fi
exit "$RC"
