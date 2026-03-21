#!/bin/bash
# Scenario: shell escape via exec
# Simulates a jailbroken AI agent spawning a root shell to gain persistent access.
# Expected: vigil's bprm_check LSM hook returns EPERM before execve completes.

set -uo pipefail

PASS=0
FAIL=0

try_exec() {
  local bin="$1"
  shift
  echo -n "  execve($bin) ... "
  if "$bin" "$@" 2>/dev/null; then
    echo "SUCCEEDED (vigil missed!)" >&2
    FAIL=$((FAIL + 1))
  else
    local rc=$?
    if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
      echo "not found (skipped)"
      PASS=$((PASS + 1))
    else
      echo "BLOCKED (exit $rc)"
      PASS=$((PASS + 1))
    fi
  fi
}

echo "=== Scenario: Shell Escape ==="
echo "Attempting to spawn interactive shells..."
echo ""

try_exec /bin/bash -c "id"
try_exec /usr/bin/bash -c "id"
try_exec /bin/sh -c "id"
try_exec /usr/bin/python3 -c "import os; os.system('id')"

echo ""
echo "Results: $PASS blocked, $FAIL escaped"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
