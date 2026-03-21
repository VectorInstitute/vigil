#!/bin/bash
# vigil demo — AI agent jailbreak scenarios
#
# Usage:
#   sudo ./demo/run_demo.sh [--profile claude-code|gemini|ollama]
#
# This script:
#   1. Starts vigil with the chosen AI agent profile
#   2. Runs attack scenarios simulating a jailbroken agent
#   3. Streams the real-time audit log showing what was blocked
#
# Requirements:
#   - Linux 5.7+ with lsm=bpf active (check: cat /sys/kernel/security/lsm)
#   - Root privileges (eBPF program loading)
#   - vigil binary at ./vigil or /usr/local/bin/vigil

set -euo pipefail

PROFILE="${1:-claude-code}"
# Strip leading "--profile " flag if passed
PROFILE="${PROFILE#--profile }"

VIGIL_BIN="${VIGIL_BIN:-./vigil}"
if ! command -v "$VIGIL_BIN" &>/dev/null; then
  VIGIL_BIN="/usr/local/bin/vigil"
fi

PROFILE_FILE="profiles/${PROFILE}.yaml"
if [ ! -f "$PROFILE_FILE" ]; then
  echo "ERROR: profile not found: $PROFILE_FILE"
  echo "Available profiles:"
  ls profiles/*.yaml 2>/dev/null | sed 's|profiles/||;s|\.yaml||' | sed 's/^/  /'
  exit 1
fi

BPF_OBJ="${BPF_OBJ:-/usr/lib/vigil/vigil.bpf.o}"
if [ ! -f "$BPF_OBJ" ]; then
  BPF_OBJ="bpf/vigil.bpf.o"
fi

AUDIT_LOG="/tmp/vigil-demo-audit.jsonl"
DEMO_DIR="$(dirname "$0")"

# ── Check requirements ────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: vigil requires root to load eBPF programs."
  echo "Run: sudo $0 $*"
  exit 1
fi

LSM_ACTIVE=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if ! echo "$LSM_ACTIVE" | grep -q "bpf"; then
  cat <<EOF

ERROR: BPF LSM is not active.

  Current LSM stack: ${LSM_ACTIVE:-unknown}

  Fix:
    1. Add 'lsm=bpf' to GRUB_CMDLINE_LINUX in /etc/default/grub
    2. Run: sudo update-grub && sudo reboot
    3. Verify: cat /sys/kernel/security/lsm

EOF
  exit 1
fi

# ── Print header ──────────────────────────────────────────────────────────────

clear
cat <<BANNER

  ██╗   ██╗██╗ ██████╗ ██╗██╗
  ██║   ██║██║██╔════╝ ██║██║
  ██║   ██║██║██║  ███╗██║██║
  ╚██╗ ██╔╝██║██║   ██║██║██║
   ╚████╔╝ ██║╚██████╔╝██║███████╗
    ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝

  eBPF runtime security for AI inference workloads
  Profile: ${PROFILE}

BANNER

echo "  Kernel LSM stack: $LSM_ACTIVE"
echo "  Audit log: $AUDIT_LOG"
echo ""

# ── Start vigil ───────────────────────────────────────────────────────────────

rm -f "$AUDIT_LOG"
echo "[vigil] loading eBPF programs..."
"$VIGIL_BIN" watch \
  --profile "$PROFILE_FILE" \
  --bpf-obj "$BPF_OBJ" \
  >> "$AUDIT_LOG" 2>&1 &
VIGIL_PID=$!
trap 'kill $VIGIL_PID 2>/dev/null; echo ""; echo "[vigil] stopped"' EXIT

# Give vigil a moment to attach
sleep 1

if ! kill -0 "$VIGIL_PID" 2>/dev/null; then
  echo "ERROR: vigil failed to start. Check $AUDIT_LOG"
  cat "$AUDIT_LOG"
  exit 1
fi

echo "[vigil] attached — PID $VIGIL_PID"
echo ""

# ── Stream audit log in background ───────────────────────────────────────────

stream_audit() {
  tail -F "$AUDIT_LOG" 2>/dev/null | while IFS= read -r line; do
    # Colour-code BLOCK vs ALLOW
    if echo "$line" | grep -q '"action":"BLOCK"'; then
      printf '\033[0;31m%s\033[0m\n' "$line"
    elif echo "$line" | grep -q '"action":"ALLOW"'; then
      printf '\033[0;32m%s\033[0m\n' "$line"
    else
      echo "$line"
    fi
  done
}
stream_audit &
TAIL_PID=$!
trap 'kill $VIGIL_PID $TAIL_PID 2>/dev/null; echo ""; echo "[vigil] stopped"' EXIT

# ── Run scenarios ─────────────────────────────────────────────────────────────

run_scenario() {
  local name="$1"
  local script="$2"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  [scenario] $name"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  bash "$DEMO_DIR/scenarios/$script" && true
  echo ""
  echo "  (audit events above — red=BLOCK, green=ALLOW)"
  sleep 1
}

run_scenario "1/3  Credential Theft" "credential_theft.sh"
run_scenario "2/3  Shell Escape via exec" "shell_escape.sh"
run_scenario "3/3  Network Exfiltration" "network_exfil.sh"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Demo complete — audit summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0)
BLOCKS=$(grep -c '"action":"BLOCK"' "$AUDIT_LOG" 2>/dev/null || echo 0)
ALLOWS=$(grep -c '"action":"ALLOW"' "$AUDIT_LOG" 2>/dev/null || echo 0)

echo "  Total events : $TOTAL"
printf "  \033[0;31mBLOCKED\033[0m      : $BLOCKS\n"
printf "  \033[0;32mALLOWED\033[0m      : $ALLOWS\n"
echo ""
echo "  Full audit log: $AUDIT_LOG"
echo ""
