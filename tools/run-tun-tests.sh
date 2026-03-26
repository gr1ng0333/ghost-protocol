#!/bin/bash
export PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /root/ghost

cleanup() {
    ip rule del pref 100 2>/dev/null
    for i in 1 2 3 4 5; do ip rule del pref 110 2>/dev/null; done
    ip rule del pref 120 2>/dev/null
    ip rule del pref 130 2>/dev/null
    ip route flush table 100 2>/dev/null
    for d in ghosttest0 ghostrt0 ghostrt1 ghostrt2 ghostrt3; do ip link del $d 2>/dev/null; done
    resolvectl revert ens3 2>/dev/null
}
trap cleanup EXIT

GHOST_TUN_TESTS=1 go test -v -count=1 -timeout=120s ./internal/proxy/... > /tmp/tun-results.txt 2>&1
echo "EXIT_CODE=$?" >> /tmp/tun-results.txt
cleanup
echo "DONE" >> /tmp/tun-results.txt
