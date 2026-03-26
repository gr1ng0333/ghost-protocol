#!/bin/bash
echo "=== 10-minute stability test (stealth mode) ==="
START=$(date +%s)
COUNT=0
FAIL=0
while [ $(($(date +%s) - START)) -lt 600 ]; do
  COUNT=$((COUNT + 1))
  STATUS=$(curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{http_code}" https://www.google.com/ --max-time 15 2>&1)
  if [ "$STATUS" = "200" ]; then
    echo "$(date +%H:%M:%S) #$COUNT: OK"
  else
    FAIL=$((FAIL + 1))
    echo "$(date +%H:%M:%S) #$COUNT: FAIL ($STATUS)"
  fi
  sleep 30
done
echo "=== Result: $COUNT requests, $FAIL failures ==="

echo ""
echo "=== Reconnection events ==="
grep -c "reconnect\|Reconnect\|connection dead\|freeze" /var/log/ghost-client.log 2>/dev/null || echo "0"
echo "=== Last 20 log lines ==="
tail -20 /var/log/ghost-client.log
