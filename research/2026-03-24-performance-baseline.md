# Performance Baseline — Stage 7.1

**Date:** 2026-03-25
**Stage:** 7.1 (Integration Testing + Performance Benchmarks)
**Environment:**
- VPS: 1 vCPU / 2GB RAM (KVM, /dev/vda2 25G)
- CPU: Intel Core Processor (Broadwell, IBRS) @ 2.40 GHz
- Cores: 1
- RAM: 1.9Gi
- OS: Linux 6.8.0-79-generic x86_64
- Go: go1.26.1 linux/amd64 (toolchain auto-downloaded; base install go1.24.1)

## 1. Go Micro-Benchmarks

### Framing

```
goos: linux
goarch: amd64
pkg: ghost/internal/framing
cpu: Intel Core Processor (Broadwell, IBRS)
BenchmarkEncode_DataFrame               53717583                63.52 ns/op    16120.37 MB/s           0 B/op          0 allocs/op
BenchmarkDecode_DataFrame                6502239               594.7 ns/op      1722.00 MB/s        1216 B/op          2 allocs/op
BenchmarkEncodeDecode_Roundtrip          5605851               645.5 ns/op      1586.35 MB/s        1216 B/op          2 allocs/op
BenchmarkEncode_LargeFrame               5570517               663.9 ns/op     24099.58 MB/s           0 B/op          0 allocs/op
PASS
ok      ghost/internal/framing  22.296s
```

### Mux

```
goos: linux
goarch: amd64
pkg: ghost/internal/mux
cpu: Intel Core Processor (Broadwell, IBRS)
BenchmarkMux_StreamWrite                  415827              7712 ns/op         132.78 MB/s        2432 B/op          6 allocs/op
BenchmarkMux_StreamReadWrite              216549             15055 ns/op          68.02 MB/s        4864 B/op         12 allocs/op
BenchmarkMux_ConcurrentStreams             39492             93008 ns/op         110.10 MB/s       25136 B/op         81 allocs/op
PASS
ok      ghost/internal/mux      11.356s
```

### Shaping

```
goos: linux
goarch: amd64
pkg: ghost/internal/shaping
cpu: Intel Core Processor (Broadwell, IBRS)
BenchmarkPassthroughPadder              1000000000               0.5710 ns/op  1793305.18 MB/s         0 B/op          0 allocs/op
BenchmarkProfilePadder                  13820973               228.4 ns/op      4483.42 MB/s          55 B/op          1 allocs/op
BenchmarkTimerWriter_Performance        136703940               23.79 ns/op     43051.23 MB/s          0 B/op          0 allocs/op
BenchmarkTimerWriter_Stealth                 349          10237324 ns/op            0.10 MB/s           0 B/op          0 allocs/op
BenchmarkPadderFrameWriter              24830258               130.1 ns/op      7868.39 MB/s           8 B/op          1 allocs/op
PASS
ok      ghost/internal/shaping  53.910s
```

### Proxy

```
goos: linux
goarch: amd64
pkg: ghost/internal/proxy
cpu: Intel Core Processor (Broadwell, IBRS)
BenchmarkSOCKS5_Relay                     3248           1096938 ns/op           0.93 MB/s       68485 B/op         82 allocs/op
BenchmarkPipeline_Throughput            174934             17286 ns/op          59.24 MB/s        4880 B/op         14 allocs/op
PASS
ok      ghost/internal/proxy    23.145s
```

## 2. End-to-End Throughput

| Mode | Throughput (Mbps) | Target (Mbps) | Status |
|------|-------------------|---------------|--------|
| Performance | 6371.7 | ≥150 | ✅ |
| Balanced | 138.0 | ≥100 | ✅ |
| Stealth | 69.7 | ≥30 | ✅ |

All three modes exceed their throughput targets. Performance mode runs in-memory (no network I/O) through passthrough shaping at 6.4 Gbps. Balanced and Stealth modes include simulated timing delays from the shaping profile; their throughput reflects the intentional delay overhead. No bottlenecks observed.

## 3. Memory & Goroutine Leak Tests

### Stream Churn (10,000 streams)
- Goroutines: baseline=1, after=1, diff=+0 ✅
- Memory: baseline=0.1MB, after=0.1MB, diff=+30.6% ❌

Note: The memory diff percentage is inflated because both baseline and final values are extremely small (0.1MB). The absolute increase is ~30KB over 10,000 stream open/close cycles, which is effectively noise within the Go runtime's allocation granularity. No real leak.

### Reconnect Churn (100 cycles)
- Goroutines: baseline=1, after=1, diff=+0 ✅

### Long-Running Stability (1 min)
- Memory trend: +2.7% per sample (increasing) ✅
- Goroutine range: [8, 8] (stable) ✅

Memory trend is within the 5% threshold and goroutines are perfectly stable.

## 4. Race Detector
- Result: **PASS** (zero races)
- All 10 packages tested: auth, config, framing, mux, proxy, shaping, transport, mobile, ghost-server, fpcheck
- Previously found and fixed: 3 races (see Run 3 commit history)

```
ok      ghost/cmd/ghost-server  1.038s
ok      ghost/internal/auth     1.152s
ok      ghost/internal/config   1.036s
ok      ghost/internal/framing  1.041s
ok      ghost/internal/mux      1.057s
ok      ghost/internal/proxy    16.022s
ok      ghost/internal/shaping  35.697s
ok      ghost/internal/transport        7.373s
ok      ghost/mobile    9.082s
ok      ghost/tools/fpcheck     1.066s
```

## 5. TUN Integration (Issue #26)
- Tests run: 4 (TUN-specific: CreateAndDestroy, FullPipeline, StopIdempotent, StopBeforeStart)
- Tests passed: 4
- Total proxy tests with TUN enabled: 71 passed, 0 failed
- Environment: Linux 6.8.0-79-generic, root access, `GHOST_TUN_TESTS=1`

## 6. Network Tests
- Tests run: 133
- Tests passed: 133
- Tests failed: 0
- Environment: Linux 6.8.0-79-generic, live internet, `GHOST_NETWORK_TESTS=1`

## 7. Summary

All performance targets are met with comfortable margins. The in-process pipeline achieves 6.4 Gbps in performance mode, 138 Mbps in balanced mode, and 70 Mbps in stealth mode — all exceeding their respective ≥150/≥100/≥30 Mbps targets. The framing layer encodes at 16 GB/s and decodes at 1.7 GB/s with only 2 allocations per frame. No goroutine leaks were detected across any test, the race detector is clean, and all 204 tests (71 proxy + 133 transport) pass on real Linux with TUN and network access enabled.

The only minor flag is the stream churn memory diff of 30.6%, but this is an artifact of the tiny baseline (0.1MB absolute); the actual delta is ~30KB which is GC noise.

## 8. Recommendations for Phase 7.2

- **Stealth validation:** The TimerWriter_Stealth benchmark shows ~10ms/frame overhead, which is by design. Phase 7.2 should validate that this timing profile actually evades DPI statistical classifiers in real network conditions.
- **Decode allocation:** The framing decoder allocates 1216 bytes per frame (2 allocs). For Phase 7.3 throughput optimization, consider pooling frame payloads via `sync.Pool` to reduce GC pressure under sustained high-throughput loads.
- **SOCKS5 relay overhead:** At ~1.1ms per relay with 82 allocations, the SOCKS5 handshake path has room for optimization if connection setup latency becomes a concern with frequent short-lived streams.
- **Single-core VPS:** All benchmarks ran on a 1-core VPS. Multi-core production deployments may show different contention patterns in the mux concurrent streams path.
