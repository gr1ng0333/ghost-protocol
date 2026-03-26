#!/bin/bash
# Update all 3 configs to include the profile path
for cfg in /etc/ghost/client-stealth.yaml /etc/ghost/client-balanced.yaml /etc/ghost/client-perf.yaml; do
    sed -i 's|profile_path: ""|profile_path: "/etc/ghost/chrome_browsing.json"|' "$cfg"
done

echo "=== Updated configs ==="
grep profile_path /etc/ghost/client-*.yaml

# Restart ghost-client in stealth mode
echo "=== Restarting ghost-client ==="
pkill ghost-client || true
sleep 2

nohup /usr/local/bin/ghost-client -config /etc/ghost/client-stealth.yaml > /var/log/ghost-client.log 2>&1 &
sleep 3

echo "=== Status ==="
pgrep -a ghost-client
ss -tlnp | grep 1080
tail -10 /var/log/ghost-client.log
