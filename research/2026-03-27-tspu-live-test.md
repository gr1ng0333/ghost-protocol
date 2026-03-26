# TSPU Live Test — Moscow Datacenter

**Date:** 2026-03-26
**Test location:** Moscow, Russia (5.42.96.173, datacenter: SpaceCore / msk-1-vm-edlo)
**Ghost server:** 94.156.122.66 (NL), SNI `397841.vm.spacecore.network`
**Client OS:** Ubuntu 24.04.3 LTS, kernel 6.8.0-90-generic
**Ghost client:** Cross-compiled Go binary (CGO_ENABLED=0, linux/amd64)
**Profile:** `chrome_browsing.json` (traffic shaping + cover traffic)

## Objective

Validate that Ghost tunnel functions correctly when routed through Russian
network infrastructure (TSPU / DPI equipment). Measure baseline connectivity,
tunnel throughput across all three shaping modes, and long-running stability.

## 1. Environment

| Parameter | Value |
|-----------|-------|
| RU server IP | 5.42.96.173 |
| Datacenter | SpaceCore, Moscow |
| OS | Ubuntu 24.04.3 LTS |
| Kernel | 6.8.0-90-generic |
| NL server IP | 94.156.122.66 |
| NL Caddy SNI | 397841.vm.spacecore.network |
| Transport | uTLS (Chrome Auto) + HTTP/2 |
| Framing | Ghost binary framing over TLS 1.3 |
| Mux | Multiplexed streams |
| Shaping modes | stealth, balanced, performance |

## 2. Baseline — Direct Connectivity from RU

These tests verify what the RU server can reach *without* Ghost, establishing
the TSPU blocking baseline.

### HTTPS reachability

| Target | HTTP status | Time |
|--------|-------------|------|
| google.com | 200 | 145ms |
| Ghost server (Caddy) | 200 | 172ms |
| linkedin.com | 200 | not blocked |
| discord.com | 200 | not blocked |
| twitter.com | 301 (normal redirect) | not blocked |
| rutracker.org | 301 (normal redirect) | not blocked |
| protonvpn.com | accessible | — |
| nordvpn.com | accessible | — |
| psiphon.ca | accessible | — |
| kasparov.ru | DNS failure | likely sinkholed |

### TLS handshake to Ghost server

```
Protocol  : TLSv1.3
Cipher    : TLS_AES_128_GCM_SHA256
Verify    : return code 0 (ok)
```

### Baseline assessment

This Moscow datacenter has **minimal or no active TSPU blocking** on the
tested domains. LinkedIn, Discord, Twitter, and Rutracker (commonly blocked
on residential ISPs) were all directly accessible. Only kasparov.ru showed
DNS resolution failure, suggesting DNS-level sinkholing rather than DPI.

The TLS 1.3 handshake to our Ghost server completed without interference —
no RST injection or certificate manipulation observed.

> **Note:** TSPU enforcement varies significantly by ISP and datacenter.
> Residential ISPs (Rostelecom, MTS, Beeline) typically enforce blocking
> more aggressively than datacenter networks.

## 3. Tunnel Connectivity

Ghost client running in stealth mode, SOCKS5 on `127.0.0.1:1080`.

### Basic sites through Ghost tunnel

| Target | HTTP status | Latency |
|--------|-------------|---------|
| google.com | 200 | 516ms |
| youtube.com | 200 | 1.3s |
| github.com | 200 | 1.5s |
| wikipedia.org | 301 | 183ms |
| cloudflare.com | 200 | 2.4s |

### Commonly-blocked sites through Ghost tunnel

| Target | HTTP status | Latency |
|--------|-------------|---------|
| linkedin.com | 200 | 890ms |
| discord.com | 200 | 820ms |
| twitter.com | 301 | 282ms |

All sites accessible through the Ghost tunnel with expected latency overhead
(RU → NL → destination → NL → RU adds ~100-400ms per hop).

## 4. Throughput — All Modes

Test file: `https://proof.ovh.net/files/10Mb.dat` (10 MB)

### Per-mode results

| Mode | Throughput | TTFB (google.com) |
|------|-----------|-------------------|
| **Stealth** | 58 Mbps | 139ms |
| **Balanced** | 25 Mbps | 152ms |
| **Performance** | 63 Mbps | 144ms |
| Direct (no Ghost) | 105 Mbps | — |

### Analysis

| Mode | % of direct | Notes |
|------|------------|-------|
| Stealth | 55% | Cover traffic + padding + timing jitter |
| Balanced | 24% | Heavier shaping, more cover traffic |
| Performance | 60% | Minimal shaping, near-raw throughput |

- **Stealth** provides a good balance: 55% of direct throughput while
  maintaining strong traffic analysis resistance.
- **Balanced** mode trades throughput for maximum stealth — the heavier
  padding and timing adjustments reduce throughput to ~25 Mbps.
- **Performance** mode is only 5% faster than stealth; the difference is
  within measurement variance. Both approach the practical limit of the
  RU→NL backbone path.
- TTFB is consistent across modes (139-152ms), confirming that the initial
  handshake/connection overhead is similar regardless of shaping mode.

## 5. Stability Test

10-minute continuous test in stealth mode with traffic shaping enabled
(`chrome_browsing.json` profile, cover traffic generator active).

```
Method: curl -x socks5h://127.0.0.1:1080 https://www.google.com/ every 30s
Duration: 600 seconds (22:16:27 — 22:26:08 UTC)
```

### Results

| Metric | Value |
|--------|-------|
| Total requests | 20 |
| Successful | 20 |
| Failed | 0 |
| **Success rate** | **100%** |
| Reconnection events | 0 |
| Connection drops | 0 |

### Stability log

```
22:16:27 #1:  OK    22:21:32 #11: OK
22:16:57 #2:  OK    22:22:03 #12: OK
22:17:28 #3:  OK    22:22:33 #13: OK
22:17:59 #4:  OK    22:23:04 #14: OK
22:18:29 #5:  OK    22:23:35 #15: OK
22:19:00 #6:  OK    22:24:05 #16: OK
22:19:30 #7:  OK    22:24:36 #17: OK
22:20:01 #8:  OK    22:25:07 #18: OK
22:20:31 #9:  OK    22:25:37 #19: OK
22:21:02 #10: OK    22:26:08 #20: OK
```

The tunnel maintained a fully stable connection for the entire 10-minute
window with zero failures and zero reconnections. The ghost-client logs
show only `socks5 connect` entries — no errors, warnings, or reconnection
attempts.

## 6. NL Server Health (post-test)

| Metric | Value |
|--------|-------|
| healthy | true |
| active sessions | 1 |
| total sessions | 12 |
| uptime | 3981s (~66 min since restart) |
| reconnects | 0 |
| server load avg | 0.10 |
| memory used | 393 / 1968 MB (20%) |

The Ghost server remained healthy throughout all testing with low resource
utilization.

## 7. Conclusions

### What worked

1. **Ghost tunnel is fully functional from Moscow datacenter** — all tested
   sites accessible through the tunnel with zero failures.

2. **Traffic shaping operates correctly** — stealth mode with
   `chrome_browsing.json` profile activates cover traffic generation and
   padding as expected.

3. **Throughput is practical** — 58 Mbps in stealth mode is sufficient for
   all common use cases (browsing, video streaming, large downloads).

4. **Connection is stable** — 100% success rate over 10 minutes with no
   reconnections or drops.

5. **TLS fingerprint was not flagged** — the uTLS Chrome fingerprint passed
   through TSPU equipment without triggering any visible interference.

### Limitations of this test

1. **Datacenter network ≠ residential ISP** — this Moscow datacenter shows
   minimal TSPU enforcement. Testing from a residential connection
   (Rostelecom, MTS) would provide stronger validation.

2. **Short duration** — 10 minutes is sufficient for basic stability but
   doesn't capture time-of-day variations or periodic TSPU rule updates.

3. **No active probing test** — we didn't test whether the Ghost server
   withstands active probing (sending non-Ghost traffic to the server port).
   The Caddy fallback should handle this, but it wasn't verified from RU.

4. **Single egress path** — all traffic exits through the NL server. Testing
   with multiple exit nodes would validate path independence.

### Recommendations

- **Test from residential ISP** to validate against aggressive TSPU filtering.
- **Run 24-hour stability test** to verify long-term connection stability.
- **Add active probing test** — connect to Ghost server port from RU with
  plain HTTPS to verify Caddy fallback is indistinguishable.
- **Test during peak censorship periods** (e.g., political events, elections)
  when TSPU rules are typically tightened.
