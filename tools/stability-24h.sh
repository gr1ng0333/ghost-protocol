#!/bin/bash
# Ghost Protocol — 24h Stability Test
# Run from a machine with ghost-client active (SOCKS5 on 127.0.0.1:1080)
# Usage: ./stability-24h.sh [duration_hours] [interval_seconds]
# Default: 24h duration, 60s interval

set -euo pipefail

DURATION_HOURS=${1:-24}
INTERVAL=${2:-60}
SOCKS="socks5h://127.0.0.1:1080"
LOG="stability-$(date +%Y%m%d-%H%M).log"

# Calculate end time
DURATION_SECS=$((DURATION_HOURS * 3600))
START=$(date +%s)
END=$((START + DURATION_SECS))

# Counters
TOTAL=0
OK=0
FAIL=0
TIMEOUT=0

# Latency tracking
LATENCY_SUM=0
LATENCY_MAX=0
LATENCY_MIN=999999

# Test targets (rotate through these)
TARGETS=(
    "https://www.google.com/"
    "https://www.cloudflare.com/"
    "https://www.wikipedia.org/"
    "https://httpbin.org/ip"
    "https://example.com/"
)

log() {
    echo "$1" | tee -a "$LOG"
}

log "=== Ghost 24h Stability Test ==="
log "Start: $(date -Iseconds)"
log "Duration: ${DURATION_HOURS}h"
log "Proxy: $SOCKS"
log "Interval: ${INTERVAL}s"
log "Targets: ${#TARGETS[@]}"
log "================================"
log ""

# Main loop
while [ "$(date +%s)" -lt "$END" ]; do
    TOTAL=$((TOTAL + 1))

    # Pick target (round-robin)
    IDX=$((TOTAL % ${#TARGETS[@]}))
    TARGET=${TARGETS[$IDX]}

    # Make request
    RESULT=$(curl -x "$SOCKS" -o /dev/null -s \
        -w "%{http_code} %{time_total} %{time_connect}" \
        --connect-timeout 30 --max-time 60 \
        "$TARGET" 2>&1) || true

    CODE=$(echo "$RESULT" | awk '{print $1}')
    TIME=$(echo "$RESULT" | awk '{print $2}')
    CONN_TIME=$(echo "$RESULT" | awk '{print $3}')

    # Evaluate result
    if [[ "$CODE" =~ ^(200|301|302|304)$ ]]; then
        OK=$((OK + 1))
        STATUS="OK"

        # Track latency (integer ms for bash arithmetic)
        TIME_MS=$(echo "$TIME" | awk '{printf "%d", $1 * 1000}')
        LATENCY_SUM=$((LATENCY_SUM + TIME_MS))
        [ "$TIME_MS" -gt "$LATENCY_MAX" ] && LATENCY_MAX=$TIME_MS
        [ "$TIME_MS" -lt "$LATENCY_MIN" ] && LATENCY_MIN=$TIME_MS
    elif [ "$CODE" = "000" ]; then
        TIMEOUT=$((TIMEOUT + 1))
        STATUS="TIMEOUT"
    else
        FAIL=$((FAIL + 1))
        STATUS="FAIL"
    fi

    # Log every request
    ELAPSED=$(( ($(date +%s) - START) / 60 ))
    log "$(date +%H:%M:%S) #${TOTAL} ${STATUS} code=${CODE} time=${TIME}s conn=${CONN_TIME}s target=$(basename "$TARGET") [${ELAPSED}m elapsed]"

    # Every 60 requests: print summary
    if [ $((TOTAL % 60)) -eq 0 ]; then
        RATE=$((OK * 100 / TOTAL))
        log ""
        log "--- Checkpoint at #${TOTAL} (${ELAPSED}m) ---"
        log "Success: ${OK}/${TOTAL} (${RATE}%)"
        log "Timeouts: $TIMEOUT, Failures: $FAIL"
        if [ "$OK" -gt 0 ]; then
            AVG_MS=$((LATENCY_SUM / OK))
            log "Latency: avg=${AVG_MS}ms, min=${LATENCY_MIN}ms, max=${LATENCY_MAX}ms"
        fi
        log "---"
        log ""
    fi

    sleep "$INTERVAL"
done

# Final summary
log ""
log "=========== FINAL SUMMARY ==========="
log "Duration: ${DURATION_HOURS}h"
log "Total requests: $TOTAL"
log "Successful: $OK"
log "Failed: $FAIL"
log "Timeouts: $TIMEOUT"
if [ "$TOTAL" -gt 0 ]; then
    RATE=$((OK * 100 / TOTAL))
    log "Success rate: ${RATE}%"
fi
if [ "$OK" -gt 0 ]; then
    AVG_MS=$((LATENCY_SUM / OK))
    log "Latency: avg=${AVG_MS}ms, min=${LATENCY_MIN}ms, max=${LATENCY_MAX}ms"
fi
log "Log file: $LOG"
log "======================================"
