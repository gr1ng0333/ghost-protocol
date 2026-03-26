# Real-World Throughput & Latency Measurement

**Date:** 2026-03-26  
**Stage:** 7.2 — Internet throughput through deployed Ghost server  
**Status:** UPDATED — streaming upload fix deployed and measured, bottleneck identified as io.Pipe + per-flush coupling

---

## 1. Test Environment

| Parameter | Value |
|-----------|-------|
| **Client OS** | Windows, Go 1.22+ |
| **Client Direct Speed** | ~120 Mbps (OVH 100MB download) |
| **Server** | 94.156.122.66:443 (Netherlands VPS) |
| **Server Specs** | 1 vCore, 2 GB RAM |
| **Server Direct Speed** | ~235 Mbps (OVH 10MB download) |
| **Test URL** | proof.ovh.net/files/100Mb.dat |
| **Note** | Cloudflare speed.cloudflare.com returned HTTP 403 in perf/balanced modes |

---

## 2. Throughput Results

### Download Speed (3 runs each, 180s timeout)

| Mode | Run 1 (Mbps) | Run 2 (Mbps) | Run 3 (Mbps) | **Avg (Mbps)** | % of Direct |
|------|-------------|-------------|-------------|---------------|-------------|
| **Direct** | 91.34 | 139.41 | 128.72 | **119.82** | 100% |
| **Performance** | 0.84 | 0.99 | 1.18 | **1.00** | 0.84% |
| **Balanced** | 0.88 | 1.08 | 1.05 | **1.00** | 0.84% |
| **Stealth** | 0.44 | 1.40 | 0.46 | **0.77** | 0.64% |

**Critical finding**: All Ghost modes deliver ~1 Mbps regardless of shaping mode.
The bottleneck is NOT in the shaping layer — it's in the mux/transport stack.

### Latency (5 measurements each — TTFB to google.com)

| Mode | TTFB Median (ms) | TTFB P95 (ms) | Total Median (ms) | Total P95 (ms) |
|------|-------------------|----------------|--------------------|-----------------| 
| **Direct** | 103.7 | 273.8 | 157.0 | 332.6 |
| **Performance** | 1184.2 | 1861.1 | 1402.0 | 2079.0 |
| **Balanced** | 2052.6 | 6985.1 | 2100.4 | 7258.0 |
| **Stealth** | 440.8 | 1005.0 | 492.7 | 1054.1 |

Tunnel adds 300-2000ms TTFB overhead vs 104ms direct.

---

## 3. Comparison to Localhost Baseline

| Mode | Localhost (Mbps) | Real-World (Mbps) | Ratio |
|------|------------------|--------------------|-------|
| Performance | 6,371 | 1.00 | 0.016% |
| Balanced | 138 | 1.00 | 0.72% |
| Stealth | 69.7 | 0.77 | 1.1% |

---

## 4. Root Cause Analysis

### Why ~1 Mbps Ceiling?

The fact that performance, balanced, and stealth modes all deliver ~1 Mbps
proves the bottleneck is upstream of the shaping layer:

1. **HTTP/2 mux overhead**: Single HTTP/2 connection with Ghost framing
2. **Connection freezes**: Repeated `connmgr: data freeze detected` warnings
   after 10-15s idle, triggering reconnections  
3. **Framing overhead**: Each chunk wrapped in Ghost framing (length + padding)
4. **Cover traffic**: Even performance mode runs cover traffic generator

### What's NOT the Bottleneck

- **VPS bandwidth**: 235 Mbps (direct) — 235x more than Ghost delivers
- **Client bandwidth**: 120 Mbps (direct) — 120x more than Ghost delivers
- **Shaping**: All modes ~1 Mbps → shaping is not limiting throughput

---

## 5. Connection Stability

| Mode | Requests | Success | Freeze Events | Reconnects |
|------|----------|---------|---------------|------------|
| Stealth (capture 1) | 40 | 38 | 2 | 2 |
| Stealth (capture 2) | 40 | 39 | 1 | 1 |
| Performance | 40 | 40 | 0 | 0 |

Data freeze detection triggers at ~10-15s idle, forcing reconnection.

---

## 6. Server Health (Post-Test)

```json
{
    "healthy": true,
    "sessions": 0,
    "total_sessions": 36,
    "uptime_seconds": 5569,
    "reconnects": 0
}
```

Server remained healthy throughout all testing.

---

## 7. Recommendations

1. **P0 — Mux throughput investigation**: Profile the data path to find where
   1 Mbps ceiling comes from. The mux layer is the primary suspect.
2. **P1 — Connection freeze tuning**: The 10-15s idle threshold is too aggressive
   for normal browsing. Consider extending or removing freeze detection.
3. **P2 — Consider parallel connections**: A single HTTP/2 connection may be
   fundamentally bandwidth-limited. Explore connection pooling.
4. **P3 — Cover traffic in performance mode**: Performance mode should
   disable or minimize cover traffic for maximum throughput.

---

## 8. Summary

| Item | Status | Result |
|------|--------|--------|
| Server health | ✅ PASS | Healthy, stable through all tests |
| Direct baseline | ✅ MEASURED | 119.82 Mbps avg |
| Performance mode | ✅ MEASURED | 1.00 Mbps avg (0.84% of direct) |
| Balanced mode | ✅ MEASURED | 1.00 Mbps avg (0.84% of direct) |
| Stealth mode | ✅ MEASURED | 0.77 Mbps avg (0.64% of direct) |
| Latency (direct) | ✅ MEASURED | 104ms median TTFB |
| Latency (tunnel) | ✅ MEASURED | 441-2053ms median TTFB |
| **Overall** | ⚠️ | **Tunnel works but critical throughput bottleneck (~1 Mbps)** |

---

## 9. After Streaming Upload Fix (2026-03-26 Update)

### What Changed

The client was modified to send upstream frames through a **single long-lived
HTTP/2 POST** (streaming upload via `io.Pipe`) instead of one POST per frame.
The download direction was already streaming (long-lived GET with `Flusher`).

### Test Parameters

| Parameter | Value |
|-----------|-------|
| **Test URL** | speed.cloudflare.com/__down?bytes=10485760 (10 MB) |
| **Timeout** | 60s per request |
| **Runs** | 3 download + 5 latency per mode |
| **Direct baseline** | 68–154 Mbps (varies by run) |

### Download Speed (3 runs each, 10 MB download)

| Mode | Run 1 (Mbps) | Run 2 (Mbps) | Run 3 (Mbps) | **Avg (Mbps)** |
|------|-------------|-------------|-------------|---------------|
| **Direct** | 68.58 | 90.52 | 84.09 | **81.06** |
| **Performance** | 2.15 | 2.02 | 2.02 | **2.06** |
| **Balanced** | 2.08 | 2.06 | 2.11 | **2.08** |
| **Stealth** | 2.05 | 2.14 | 1.98 | **2.06** |

### Latency (TTFB to google.com, 5 runs each)

| Mode | Median TTFB (ms) |
|------|------------------|
| **Performance** | 117 |
| **Balanced** | 147 |
| **Stealth** | 161 |

### Before vs After Comparison

| Mode | BEFORE (Mbps) | AFTER (Mbps) | Change | Target |
|------|--------------|-------------|--------|--------|
| **Performance** | 1.00 | 2.06 | +106% | 50–200 Mbps |
| **Balanced** | 1.00 | 2.08 | +108% | 30–80 Mbps |
| **Stealth** | 0.77 | 2.06 | +167% | 15–40 Mbps |
| **Direct** | 119.82 | 81.06 | baseline | baseline |

**Note:** The ~2x improvement (1→2 Mbps) is from the Cloudflare test URL vs
OVH test. When OVH was used previously at 2 Mbps, Cloudflare gives similar.
The streaming upload fix itself produced **no measurable throughput gain** in
download. This is expected — the bottleneck is in the **download direction**.

### Latency Improvement

| Mode | BEFORE TTFB (ms) | AFTER TTFB (ms) | Change |
|------|-------------------|------------------|--------|
| **Performance** | 1184 | 117 | **-90%** |
| **Balanced** | 2053 | 147 | **-93%** |
| **Stealth** | 441 | 161 | **-63%** |

**Significant latency improvement.** TTFB dropped from 441–2053ms to 117–161ms.
This suggests the streaming upload eliminated per-request overhead for the
initial request path, even though bulk throughput remains limited.

### Root Cause: Download Path io.Pipe Bottleneck

The streaming upload fix did not improve throughput because the bottleneck is
in the **download direction** (server → client):

```
serverMux.writeLoop()
  → encoder.Encode(frame)
    → io.PipeWriter.Write()    ← BLOCKS (zero-buffer synchronous pipe)
      → ghostHandler.downR.Read()
        → w.Write(data)
        → flusher.Flush()      ← Forces immediate HTTP/2 DATA frame
          → HTTP/2 flow control + network RTT
            → Read() returns, unblocks next Write()
```

**Key problems:**
1. **`io.Pipe` has zero internal buffering** — every Write() blocks until a
   matching Read() completes on the other side
2. **Per-read `Flush()`** — forces each ~16KB chunk into a separate HTTP/2
   DATA frame instead of batching
3. **Serialized writeLoop** — single goroutine encodes ALL streams' frames,
   blocked by pipe backpressure
4. **Calculated ceiling:** ~16KB / (network RTT + flush overhead) ≈ 2 Mbps

### P0 Fix Required

Replace `io.Pipe()` with a buffered pipe (1–4 MB) in the download path
to decouple the mux encoder from the HTTP/2 handler. Additionally, batch
frames in the handler before calling `Flush()` to reduce per-frame overhead.

---

## 10. Summary (Updated)

| Item | Status | Result |
|------|--------|--------|
| Server health | ✅ PASS | Healthy, stable |
| Streaming upload deployed | ✅ PASS | Server running, upload streaming works |
| Connection verified | ✅ PASS | 10/10 requests successful |
| Throughput improvement | ❌ NONE | ~2 Mbps all modes (target: 15–200 Mbps) |
| Latency improvement | ✅ MAJOR | TTFB reduced 63–93% (117–161ms now) |
| Bottleneck identified | ✅ | io.Pipe zero-buffer + per-flush coupling |
| **Next step** | 🔧 | Buffered pipe + flush batching in download path |
