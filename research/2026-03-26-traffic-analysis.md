# Traffic Analysis: Ghost vs Chrome Distinguishability

**Date:** 2026-03-26  
**Status:** COMPLETED — Ghost traffic is statistically distinguishable from Chrome

## Objective

Determine whether Ghost VPN traffic is statistically distinguishable from
real Chrome HTTPS traffic when observed by deep packet inspection.

## Captures

| Capture | File | Size | Packets | Duration |
|---------|------|------|---------|----------|
| Ghost Stealth | ghost-stealth.pcap | 4.6 MB | 3,024 TCP pkts | 141s |
| Ghost Performance | ghost-perf.pcap | 4.8 MB | 3,401 TCP pkts | 142s |
| Chrome (real) | chrome-capture.pcap | 191 MB | 38,209 TCP data pkts | 450s |

- Ghost captures: 40 browsing requests each (10 sites, random delays 1-5s)
- Chrome capture: Real user browsing session (7.5 minutes)
- Ghost traffic captured on VPS (ens3 interface, port 443)
- Chrome traffic captured on Windows (all HTTPS)

---

## Ghost Stealth Mode — Traffic Statistics

### Client → Server (1,644 packets)
| Metric | Value |
|--------|-------|
| Mean packet size | 529 bytes |
| Median packet size | 66 bytes |
| Std dev | 1,663 bytes |
| P5 / P95 | 66 / 2,954 bytes |
| Mean inter-packet timing | 86.1 ms |
| Median inter-packet timing | 1.2 ms |
| Mean burst size | 2.5 packets |
| Idle periods (>500ms) | 51 |

### Server → Client (1,380 packets)
| Metric | Value |
|--------|-------|
| Mean packet size | 1,909 bytes |
| Median packet size | 123 bytes |
| Std dev | 2,753 bytes |
| P5 / P95 | 66 / 7,306 bytes |
| Mean inter-packet timing | 102.6 ms |
| Median inter-packet timing | 0.4 ms |
| Mean burst size | 3.1 packets |
| Idle periods (>500ms) | 51 |

### Flow Features
- Total bytes: 3,503,760
- Duration: 141.4s
- Unique size ratio: 0.128 (387 unique / 3024 total)
- Burst rate: 7.78/s
- No significant timing periodicity detected ✓

---

## Ghost Performance Mode — Traffic Statistics

### Client → Server (1,860 packets)
| Metric | Value |
|--------|-------|
| Mean packet size | 652 bytes |
| Median packet size | 66 bytes |
| P5 / P95 | 66 / 2,962 bytes |
| Mean inter-packet timing | 76.4 ms |
| Median inter-packet timing | 3.3 ms |
| Mean burst size | 2.2 packets |

### Server → Client (1,541 packets)
| Metric | Value |
|--------|-------|
| Mean packet size | 1,757 bytes |
| Median packet size | 106 bytes |
| P5 / P95 | 66 / 7,409 bytes |
| Mean inter-packet timing | 92.2 ms |
| Median inter-packet timing | 0.5 ms |
| Mean burst size | 2.9 packets |

### Flow Features
- Total bytes: 3,919,678
- Duration: 142.0s
- Unique size ratio: 0.131 (445 unique / 3401 total)
- Burst rate: 9.59/s
- No significant timing periodicity detected ✓

---

## Ghost vs Chrome — Statistical Comparison

### Stealth vs Chrome

| Metric | Ghost Stealth | Chrome | KS p-value |
|--------|--------------|--------|------------|
| Packets (data) | 1,642 | 38,209 | — |
| Duration (s) | 137.6 | 449.6 | — |
| Mean TCP size | 2,012 | 5,088 | **0.000000** |
| Median TCP size | 447 | 1,208 | — |
| P95 TCP size | 7,240 | 35,040 | — |
| Mean IPT (ms) | 83.9 | 11.8 | **0.000000** |
| Median IPT (ms) | 0.6 | 0.4 | — |
| Mean burst size | 3.9 | 7.5 | **0.000000** |

**KS Tests**: 4/4 distributions are DIFFERENT (p < 0.001)  
**ML Accuracy**: **96.9% ± 1.6%** (Random Forest, 5-fold CV)  
**Verdict**: ✗ Ghost stealth IS statistically distinguishable from Chrome

### Performance vs Chrome

| Metric | Ghost Perf | Chrome | KS p-value |
|--------|-----------|--------|------------|
| Packets (data) | 1,884 | 38,209 | — |
| Duration (s) | 142.0 | 449.6 | — |
| Mean TCP size | 1,961 | 5,088 | **0.000000** |
| Median TCP size | 238 | 1,208 | — |
| P95 TCP size | 8,688 | 35,040 | — |
| Mean IPT (ms) | 75.4 | 11.8 | **0.000000** |
| Median IPT (ms) | 0.8 | 0.4 | — |
| Mean burst size | 3.7 | 7.5 | **0.000000** |

**KS Tests**: 4/4 distributions are DIFFERENT (p < 0.001)  
**ML Accuracy**: **96.6% ± 2.1%** (Random Forest, 5-fold CV)  
**Verdict**: ✗ Ghost performance IS statistically distinguishable from Chrome

---

## Root Cause of Distinguishability

### 1. Packet Size Gap (Primary)
- **Ghost**: median TCP payload 238-447 bytes, P95 ~7-9 KB
- **Chrome**: median TCP payload 1,208 bytes, P95 ~35 KB  
- Ghost packets are consistently smaller — the ~1 Mbps throughput bottleneck
  prevents large data transfers, resulting in many small frames

### 2. Inter-Packet Timing (Secondary)
- **Ghost**: mean IPT 75-84 ms (slow due to mux overhead)
- **Chrome**: mean IPT 11.8 ms (fast due to direct connections)
- Ghost is ~7x slower between packets

### 3. Burst Size (Tertiary)
- **Ghost**: mean burst 3.7-3.9 packets
- **Chrome**: mean burst 7.5 packets (up to 1,668 in a burst)
- Chrome has much burstier traffic (e.g., loading images, CSS, JS in parallel)

### Key Insight

The distinguishability is primarily caused by the **throughput bottleneck**,
not by shaping parameter misconfiguration. Because Ghost tunnels all traffic
through a single HTTP/2 mux connection at ~1 Mbps, the resulting packet sizes
and timing are fundamentally different from Chrome running at full speed.

Fixing the throughput bottleneck would likely improve indistinguishability
more than any amount of shaping parameter tuning.

---

## Assessment

| Question | Answer |
|----------|--------|
| Is Ghost fast enough? | **No** — 1 Mbps vs 120 Mbps direct |
| Is Ghost distinguishable? | **Yes** — 97% ML accuracy |
| Does shaping mode matter? | **No** — all modes ~1 Mbps, equally distinguishable |
| Is the shaping engine at fault? | **No** — bottleneck is in mux/transport layer |
| Are shaping parameters correct? | **Unknown** — can't be evaluated at 1 Mbps |

---

## Recommendations

### Priority 1: Fix Throughput Bottleneck
The single biggest improvement would be fixing the ~1 Mbps ceiling in the
mux/transport layer. This would:
- Increase usability (currently barely usable for browsing)
- Allow larger packets similar to Chrome's distribution
- Enable proper evaluation of the shaping engine

### Priority 2: Re-evaluate After Throughput Fix
Once throughput is reasonable (>30 Mbps), re-run this analysis. The shaping
parameters may be adequate once packet sizes and timing naturally match Chrome.

### Priority 3: Shaping Tuning (if still needed)
If analysis still shows distinguishability after throughput fix:
- Increase max frame/TLS record sizes to allow P95 near 35 KB
- Consider larger burst sizes (Chrome does up to ~1000 packets in a burst)
- Adjust cover traffic to avoid creating an artificially steady stream

### Priority 4: Connection Freeze Detection
The `connmgr: data freeze detected` warnings trigger reconnections that
further reduce throughput. Either increase the idle threshold or disable
freeze detection for longer idle periods during browsing.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `tools/traffic-analysis/analyze_pcap.py` | Per-pcap statistical analysis |
| `tools/traffic-analysis/compare_traffic.py` | Cross-pcap KS tests + ML classifier |
| `tools/gen_traffic.go` | Browsing traffic generator through SOCKS5 |
| `tools/throughput_bench.go` | Throughput + latency measurement |
| VPS `tcpdump` (ens3 interface) | Packet capture |
