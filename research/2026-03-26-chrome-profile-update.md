# Chrome Traffic Profile Update — Empirical Analysis

**Date:** 2026-03-26
**Issue:** #20 — Update chrome_browsing.json with real Chrome traffic data
**Source:** Live Chrome browsing capture with SSLKEYLOGFILE + Wireshark

## 1. Capture Statistics

| Metric | Value |
|--------|-------|
| Capture file | `C:\tmp\chrome-capture.pcap` (191 MB) |
| Duration | 449.6 seconds (7.5 minutes) |
| Total frames | 67,533 |
| TLS application data records | 5,730 |
| TCP payload frames | 38,208 |
| Total connections (TCP streams) | 838 |
| Protocols | 100% TCP, 0% UDP/QUIC |
| Server IP | 80.71.227.193:443 |
| Client IP | 192.168.50.79 |
| TLS keylog entries | 5,018 lines |

**HTTP/2 decryption:** Failed. TShark 4.6.4 could not decrypt TLS sessions
despite valid keylog file (NSS Key Log Format with CLIENT_RANDOM, TLS 1.3 secrets).
Likely cause: Chrome session resumption — keylog captured keys for new
handshakes but existing sessions used pre-established keys. TLS debug log
confirmed: `decrypt_ssl3_record: no decoder available`.

**Impact:** Analysis uses TLS record sizes (outer encrypted layer), which is
actually *more relevant* for Ghost's purpose — this is exactly what DPI systems
observe on the wire.

## 2. TLS Record Size Distribution (What DPI Sees)

### All directions (5,730 records)
| Stat | Value |
|------|-------|
| Min | 19 |
| P5 | 52 |
| P25 | 177 |
| Median | 187 |
| P75 | 640 |
| P95 | 8,209 |
| Max | 8,230 |
| Mean | 1,636.7 |
| Std Dev | 2,879.8 |

### Client → Server (1,528 records)
| Stat | Value |
|------|-------|
| Min | 19 |
| Median | 6,394 |
| P95 | 8,209 |
| Mean | 4,486.6 |

### Server → Client (4,202 records)
| Stat | Value |
|------|-------|
| Min | 19 |
| Median | 185 |
| P95 | 4,046 |
| Mean | 600.4 |

### Key finding: Bimodal distribution
The TLS record size distribution is heavily bimodal:
- **41.1%** of all records are 150–200 bytes (small control/header records)
- **14.1%** are 8,200–8,250 bytes (full TLS records at max size)
- Long tail between 200–8,200 bytes

This is dramatically different from the old profile which assumed a smooth
distribution from 50 to 16,384 bytes.

## 3. Inter-Packet Timing Analysis

### All directions
| Stat | Value (ms) |
|------|-----------|
| Median | 1.1 |
| P75 | 42.5 |
| P95 | 452.9 |
| Mean | 78.5 |

### Lognormal fit
- **μ = 2.02, σ = 2.78**
- Median delay: e^μ = 7.5 ms
- Higher variance than old estimate (σ was 1.5)

### Intra-burst (< 50ms gap): 4,433 gaps
- Median: 0.3 ms, Mean: 5.7 ms

### Inter-burst (≥ 50ms gap): 1,296 gaps
- Median: 135.9 ms, Mean: 327.5 ms, P95: 1,197 ms

## 4. Burst Pattern Analysis

### 10ms threshold (2,090 bursts)
| Metric | Min | Median | P5 | P95 | Max |
|--------|-----|--------|----|-----|-----|
| Packets/burst | 1 | 1 | 1 | 9 | 259 |
| Bytes/burst | 19 | 201 | 52 | 11,947 | 220,895 |
| Pause (ms) | 10 | 56.5 | 13.4 | 1,006 | 2,010 |

### 50ms threshold (1,297 bursts)
| Metric | Median | P95 |
|--------|--------|-----|
| Packets/burst | 2 | 17 |
| Bytes/burst | 631 | 18,154 |
| Pause (ms) | 135.9 | 1,197 |

## 5. Session Pattern

| Metric | Median | P95 |
|--------|--------|-----|
| Connection duration | 2.8s | 199.7s |
| Bytes sent/conn | 7,451 | 38,666 |
| Bytes recv/conn | 12,496 | 142,653 |

## 6. Old vs New Profile Comparison

### Size Distribution (101-point empirical CDF)
| Percentile | OLD | NEW | Change |
|------------|-----|-----|--------|
| P0 (min) | 50 | 19 | -62% |
| P10 | 800 | 65 | -92% |
| P25 | 4,116 | 177 | -96% |
| P50 (median) | 11,085 | 187 | **-98%** |
| P75 | 14,128 | 640 | -95% |
| P90 | 15,451 | 8,209 | -47% |
| P100 (max) | 16,384 | 8,230 | -50% |

**Major finding:** The old profile dramatically overestimated frame sizes.
Real Chrome TLS records are mostly small (~187 bytes median) with a long
tail to ~8,230 bytes. The old profile had a median of 11,085 bytes — nearly
60x too large.

### Timing Distribution (lognormal)
| Param | OLD | NEW | Change |
|-------|-----|-----|--------|
| μ | 3.0 | 2.02 | -33% |
| σ | 1.5 | 2.78 | +85% |
| Median delay | 20.1 ms | 7.5 ms | -63% |

Real Chrome has faster inter-packet gaps (7.5ms vs 20.1ms median) but
higher variance (σ=2.78 vs 1.5), reflecting the bursty nature of web
browsing with short bursts and longer idle gaps.

### Burst Configuration
| Field | OLD | NEW | Change |
|-------|-----|-----|--------|
| min_burst_bytes | 10,000 | 52 | -99% |
| max_burst_bytes | 500,000 | 11,946 | -98% |
| min_pause_ms | 200 | 13 | -94% |
| max_pause_ms | 3,000 | 1,006 | -66% |
| burst_count | [3, 15] | [1, 9] | Smaller |

Real bursts are much smaller and more frequent than estimated.

## 7. Files Modified

| File | Change |
|------|--------|
| `profiles/chrome_browsing.json` | Updated all values with empirical data |
| `mobile/ghost.go` | Updated embedded `defaultProfileJSON` to match |
| `internal/shaping/stats_test.go` | Updated test expectations for new distribution |
| `tools/traffic-analysis/analyze_chrome_profile.py` | New analysis script |

## 8. Test Results

```
ok  ghost/cmd/ghost-server       1.160s
ok  ghost/internal/auth          0.802s
ok  ghost/internal/config        0.848s
ok  ghost/internal/framing       0.813s
ok  ghost/internal/mux           0.806s
ok  ghost/internal/proxy        14.118s
ok  ghost/internal/shaping      33.953s
ok  ghost/internal/transport     5.038s
ok  ghost/mobile                 9.737s
ok  ghost/tools/fpcheck          1.287s
```

All packages pass. `go build ./...` and `go vet ./...` clean.

## 9. Key Surprises

1. **Frame sizes 60x smaller than estimated.** The old profile assumed Chrome
   sends large frames (median ~11KB). Real Chrome TLS records are mostly tiny
   (~187 bytes) — these are HTTP/2 control frames, small DATA frames, and
   headers. Large records (8KB) only appear ~14% of the time.

2. **Max TLS record size is 8,230, not 16,384.** Chrome's TLS implementation
   uses ~8KB max record size, not the protocol maximum of 16KB. This aligns
   with Chrome's known `max_record_size` TLS extension usage.

3. **Bursts are tiny.** Real burst volumes are 52–12,000 bytes (p5–p95),
   not 10,000–500,000 bytes. Most "bursts" are 1–2 packets.

4. **Timing has higher variance.** Real Chrome traffic is burstier than
   assumed — fast micro-bursts (< 1ms gaps) interspersed with longer
   pauses (100–1000ms).

## 10. Recommendations

1. **Profile accuracy dramatically improved.** The new profile reflects real
   Chrome behavior observable by DPI systems.

2. **Consider adding HTTP/2 layer data.** If a fresh capture can be made
   with SSLKEYLOGFILE set *before* Chrome launches (to catch the initial
   TLS handshake), HTTP/2 DATA frame analysis would provide additional
   insight into the application-layer patterns.

3. **Consider bimodal distribution type.** The current empirical CDF captures
   the bimodal shape, but a dedicated bimodal distribution type might be
   more efficient to sample from.

4. **Re-evaluate max frame size in shaping engine.** The `maxFrameSize`
   constant should align with the real Chrome max of ~8,230 bytes rather
   than 16,384.
