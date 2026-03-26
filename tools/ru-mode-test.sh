#!/bin/bash
for MODE in stealth balanced perf; do
  echo "=============================="
  echo "=== MODE: $MODE ==="
  pkill ghost-client 2>/dev/null
  sleep 2
  nohup /usr/local/bin/ghost-client -config /etc/ghost/client-${MODE}.yaml > /var/log/ghost-client.log 2>&1 &
  sleep 5

  # Verify connection:
  CONNECT=$(curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{http_code}" https://google.com/ --max-time 15 2>&1)
  echo "Connect: HTTP $CONNECT"

  # Throughput:
  SPEED=$(curl -x socks5h://127.0.0.1:1080 -o /dev/null -w "%{speed_download}" "https://proof.ovh.net/files/10Mb.dat" --max-time 60 2>&1)
  MBPS=$(echo "scale=1; $SPEED * 8 / 1000000" | bc 2>/dev/null || echo "N/A")
  echo "Speed: $SPEED bytes/sec ($MBPS Mbps)"

  # Latency:
  TTFB=$(curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{time_starttransfer}" https://google.com/ --max-time 15 2>&1)
  TTFB_MS=$(echo "scale=0; $TTFB * 1000 / 1" | bc 2>/dev/null || echo "N/A")
  echo "TTFB: ${TTFB}s (${TTFB_MS}ms)"
  echo ""
done
