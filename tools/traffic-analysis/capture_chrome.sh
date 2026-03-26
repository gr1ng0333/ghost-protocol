#!/bin/bash
# capture_chrome.sh — Capture real Chrome HTTPS traffic to our server
#
# Usage: ./capture_chrome.sh <duration_seconds> <output_file>
# Run on VPS (94.156.122.66) while a user browses
# https://397841.vm.spacecore.network/ in Chrome.
#
# This captures genuine Chrome TLS traffic to our server (served by Caddy
# fallback), providing a reference baseline for comparison with Ghost.

set -euo pipefail

DURATION=${1:-120}
OUTPUT=${2:-/tmp/chrome-session.pcap}

echo "============================================"
echo " Chrome Reference Traffic Capture"
echo " Duration: ${DURATION}s"
echo " Output:   ${OUTPUT}"
echo "============================================"
echo ""
echo "Tell user to open Chrome and visit:"
echo "  https://397841.vm.spacecore.network/"
echo ""
echo "Browse/refresh pages for ${DURATION} seconds."
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
