#!/bin/bash
set -euo pipefail

echo "=== Ghost Performance Benchmark Suite ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Go: $(go version)"
echo "OS: $(uname -srm)"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "RAM: $(free -h | awk '/^Mem:/{print $2}')"
echo ""

# 1. Go benchmarks
echo "--- Go Benchmarks ---"
go test -bench=. -benchmem -benchtime=3s ./internal/framing/ ./internal/mux/ ./internal/shaping/ ./internal/proxy/ 2>&1 | tee /tmp/ghost-bench.txt
echo ""

# 2. Throughput test
echo "--- Throughput Test ---"
go run ./tools/benchtest/throughput/ -mode all -duration 10s 2>&1 | tee /tmp/ghost-throughput.txt
echo ""

# 3. Leak test
echo "--- Leak Test ---"
go run ./tools/benchtest/leaktest/ -test all 2>&1 | tee /tmp/ghost-leak.txt
echo ""

echo "=== Done ==="
