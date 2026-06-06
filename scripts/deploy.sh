#!/usr/bin/env bash
# Safe deployment wrapper for nixos-rebuild.
#
# Runs preflight checks BEFORE switching the profile, so a sops
# decryption failure or missing secret never leaves the machine in
# a half-transacted state.
#
# Usage:
#   ./scripts/deploy.sh                          # deploy to local machine
#   ./scripts/deploy.sh --target-host root@fw    # deploy to remote firewall
#
# What it does:
#   1. nix build — validates assertions (MAC addresses, SSH keys, etc.)
#   2. Preflight — verifies sops can decrypt secrets on the target host
#   3. nixos-rebuild switch — only runs if preflight passes

set -euo pipefail

FLAKE_REF="${FLAKE_REF:-.#firewall}"
TARGET_HOST=""
EXTRA_ARGS=()

# Parse args — extract --target-host, pass everything else through
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-host)
      TARGET_HOST="$2"
      EXTRA_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

run_on_target() {
  if [[ -n "$TARGET_HOST" ]]; then
    ssh "$TARGET_HOST" "$@"
  else
    bash -c "$*"
  fi
}

echo "── 1. Building system closure ────────────────────────────────────"
echo "   (this validates NixOS assertions: MACs, SSH keys, Mullvad config)"
CLOSURE=$(nixos-rebuild build --flake "$FLAKE_REF" "${EXTRA_ARGS[@]}" --print-out-paths 2>/dev/null \
  || nixos-rebuild build --flake "$FLAKE_REF" "${EXTRA_ARGS[@]}")
echo "   build OK"

echo "── 2. Preflight: sops decryption test ────────────────────────────"
# Verify the target host can actually decrypt the sops secrets.
# This catches: wrong age key, missing SSH host key, corrupt sops file.
SOPS_FILE="$(cd "$(dirname "$0")/.." && pwd)/secrets/mullvad.yaml"

if [[ ! -f "$SOPS_FILE" ]]; then
  echo "ERROR: secrets/mullvad.yaml not found." >&2
  echo "Run: sops secrets/mullvad.yaml" >&2
  exit 1
fi

# Get the target's age public key (derived from its SSH host key)
echo "   checking target host's age key..."
TARGET_HOST_PUBKEY=$(run_on_target 'cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null') || {
  echo "ERROR: cannot read SSH host key on target. Is the host reachable?" >&2
  exit 1
}

# Verify this host's pubkey is a sops recipient
TARGET_AGE_PUBKEY=$(echo "$TARGET_HOST_PUBKEY" | ssh-to-age 2>/dev/null) || {
  echo "ERROR: ssh-to-age failed. Install it: nix shell nixpkgs#ssh-to-age" >&2
  exit 1
}

if ! grep -q "$TARGET_AGE_PUBKEY" .sops.yaml 2>/dev/null; then
  echo "ERROR: target host's age key ($TARGET_AGE_PUBKEY) is not in .sops.yaml" >&2
  echo "Add it as a recipient and re-encrypt: sops updatekeys secrets/mullvad.yaml" >&2
  exit 1
fi

# Test actual decryption on the target
echo "   testing sops decryption on target..."
SOPS_CONTENT=$(cat "$SOPS_FILE")
DECRYPT_OK=$(run_on_target "
  command -v sops >/dev/null 2>&1 || { echo 'NO_SOPS'; exit 0; }
  echo '$SOPS_CONTENT' | sops --decrypt --input-type yaml /dev/stdin >/dev/null 2>&1 && echo OK || echo FAIL
") || DECRYPT_OK="UNREACHABLE"

case "$DECRYPT_OK" in
  OK)
    echo "   sops decryption verified on target"
    ;;
  NO_SOPS)
    # sops binary not on target — sops-nix handles decryption via its own
    # bundled binary, so just verify the key is a recipient (already done above)
    echo "   sops not installed on target (sops-nix uses its own); recipient verified"
    ;;
  FAIL)
    echo "ERROR: sops decryption FAILED on target host." >&2
    echo "The host's age key cannot decrypt secrets/mullvad.yaml." >&2
    echo "Re-encrypt with the host's key: sops updatekeys secrets/mullvad.yaml" >&2
    exit 1
    ;;
  *)
    echo "ERROR: cannot reach target host for preflight check." >&2
    exit 1
    ;;
esac

echo "── 3. Deploying ──────────────────────────────────────────────────"
nixos-rebuild switch --flake "$FLAKE_REF" "${EXTRA_ARGS[@]}"

echo "── deploy complete ───────────────────────────────────────────────"
