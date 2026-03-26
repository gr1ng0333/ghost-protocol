#!/bin/bash
# capture_ghost.sh — Capture Ghost VPN traffic on the VPS
#
# Usage: ./capture_ghost.sh <duration_seconds> <output_file>
# Run on VPS (94.156.122.66) while a Ghost client is connected and browsing.
#
# The captured traffic will contain Ghost ↔ client packets on port 443.

set -euo pipefail

DURATION=${1:-120}
OUTPUT=${2:-/tmp/ghost-session.pcap}

echo "============================================"
echo " Ghost Traffic Capture"
echo " Duration: ${DURATION}s"
echo " Output:   ${OUTPUT}"
echo "============================================"
echo ""
echo "Tell the client operator to START Ghost client and browse now."
echo "Capture begins in 3 seconds..."
sleep 3

timeout "${DURATION}" tcpdump -i eth0 -w "$OUTPUT" \
  'port 443 and not (src host 127.0.0.1 or dst host 127.0.0.1)' \
  2>/dev/null &
TCPDUMP_PID=$!

echo "tcpdump running (PID $TCPDUMP_PID)..."
echo "Waiting ${DURATION}s for capture to complete..."

# Wait for tcpdump to finish (timeout will kill it)
wait $TCPDUMP_PID 2>/dev/null || true

echo ""
echo "Capture complete: $OUTPUT"
if [ -f "$OUTPUT" ]; then
  echo "Size: $(du -h "$OUTPUT" | cut -f1)"
  echo "Packets: $(tcpdump -r "$OUTPUT" 2>/dev/null | wc -l)"
else
  echo "WARNING: Output file not found!"
fi
