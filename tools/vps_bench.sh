#!/bin/bash
echo '=== VPS LOCAL BASELINE ==='
for i in 1 2 3; do
  RESULT=$(curl -s -o /dev/null -w '%{speed_download} %{time_total}' http://127.0.0.1:9999/ --max-time 30)
  SPEED=$(echo $RESULT | awk '{printf "%.2f", $1 * 8 / 1000000}')
  TIME=$(echo $RESULT | awk '{print $2}')
  echo "Local run $i: $SPEED Mbps (${TIME}s)"
done
