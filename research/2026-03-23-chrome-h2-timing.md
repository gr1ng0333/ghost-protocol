# Research: Chrome HTTP/2 Inter-Frame Timing Patterns
Date: 2026-03-23
Stage: 3.2 (Timing Engine)
Query: Chrome HTTP/2 inter-frame timing and burst patterns

## Summary
No published academic studies were found that specifically analyze
inter-frame timing distributions for Chrome HTTP/2 DATA frames.
Most HTTP/2 traffic analysis literature focuses on encrypted TLS
record sizes and burst-level flow features, not individual frame
timing within bursts. The timing parameters in chrome_browsing.json
remain research-estimated placeholders.

## Key Findings
- HTTP/2 frame timing is rarely analyzed at per-frame granularity in literature
- Most classification work uses TLS record lengths and flow-level burst timing
- Chrome page loads exhibit burst-pause patterns tied to resource discovery
- Inter-frame delays within bursts are dominated by server response time, not client
- The research query additionally returned improved frame SIZE data (separate concern):
  45% of Chrome DATA frames are exactly 16384 bytes (point mass at max frame size),
  sub-max portion fits truncated lognormal (mu=8.05, sigma=0.92)

## Impact on Implementation
- Timing params [3.0, 1.5] (lognormal, median ~20ms) are reasonable placeholders
- Phase 7.2 must capture real Chrome session timing via tools/profcap
- Frame size distribution findings noted for future chrome_browsing.json refinement

## Sources
- Morla et al. (arXiv 2017): CDF of HTTP/2 response DATA frame sizes via pcap+SSLKEYLOGFILE
- HTTP/2 RFC 9113: MAX_FRAME_SIZE constraints
- H2Classifier research line (2019-2024): encrypted traffic classification
