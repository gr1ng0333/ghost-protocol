#!/bin/bash
set -e

echo "=== Direct HTTPS ==="
curl -s -o /dev/null -w "google.com: %{http_code} %{time_total}s\n" https://www.google.com/ --max-time 10
curl -s -o /dev/null -w "ghost-server: %{http_code} %{time_total}s\n" https://397841.vm.spacecore.network/ --max-time 10

echo ""
echo "=== Blocked domains ==="
for SITE in https://www.linkedin.com/ https://discord.com/ https://twitter.com/ https://rutracker.org/; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SITE" --max-time 10 2>&1)
  echo "$SITE -> HTTP $CODE"
  sleep 1
done

echo ""
echo "=== Raw TLS handshake to our server ==="
echo | timeout 5 openssl s_client -connect 94.156.122.66:443 -servername 397841.vm.spacecore.network 2>&1 | grep -E "Verify|Protocol|Cipher" || echo "TLS handshake failed or timed out"
