#!/bin/bash
echo "=== Ghost Tunnel Connectivity ==="
echo "--- Basic sites ---"
for SITE in https://www.google.com/ https://www.youtube.com/ https://github.com/ https://en.wikipedia.org/ https://www.cloudflare.com/; do
  RESULT=$(curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{http_code} %{time_total}s" "$SITE" --max-time 15 2>&1)
  echo "$SITE -> $RESULT"
  sleep 1
done

echo ""
echo "--- Blocked sites through Ghost ---"
for SITE in https://www.linkedin.com/ https://discord.com/ https://twitter.com/; do
  RESULT=$(curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{http_code} %{time_total}s" "$SITE" --max-time 15 2>&1)
  echo "$SITE (through Ghost) -> $RESULT"
  sleep 1
done

echo ""
echo "=== Throughput through Ghost tunnel ==="
for run in 1 2 3; do
  curl -x socks5h://127.0.0.1:1080 -o /dev/null -w "Run $run: %{speed_download} bytes/sec (%{time_total}s)\n" "https://proof.ovh.net/files/10Mb.dat" --max-time 60 2>&1
  sleep 2
done

echo ""
echo "=== Direct throughput (no Ghost, for baseline) ==="
curl -o /dev/null -w "Direct: %{speed_download} bytes/sec (%{time_total}s)\n" "https://proof.ovh.net/files/10Mb.dat" --max-time 60
