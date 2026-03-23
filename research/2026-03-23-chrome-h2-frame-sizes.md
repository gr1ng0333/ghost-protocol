# Research: Chrome HTTP/2 DATA Frame Size Distribution
Date: 2026-03-23
Stage: 3.1 (Padding Engine)
Query: Chrome HTTP/2 DATA frame size distribution for traffic profile modeling

## Summary
Chrome HTTP/2 frame sizes follow a bimodal distribution, not a simple
parametric model. The majority (~70%) of DATA frames are large, clustered
near the 16384-byte maximum. About 20% are medium (1-5KB) and ~10% are
small (<1KB). This is because large web resources (images, JS, CSS) are
split into maximum-size frames, while only tail chunks and small resources
produce smaller frames.

## Key Findings
- Distribution is bimodal: peak at ~16KB and peak at <<1KB
- ~70% of frames are >5KB (most near 16384), ~20% are 1-5KB, ~10% are <1KB
- Pure lognormal (mu~8-9, sigma~1) insufficient — misses 16KB mode
- HTTP/2 default MAX_FRAME_SIZE = 16384, Chrome does not override this
- Chrome SETTINGS: INITIAL_WINDOW_SIZE=6291456, allowing burst of full frames
- No published datasets with per-frame size analysis of Chrome HTTP/2 found
- LHS Nancy dataset (HTTP/2 traffic) exists but is currently unavailable

## Impact on Implementation
- chrome_browsing.json uses "empirical" distribution type with 101-point CDF
- CDF encodes bimodal shape: rapid rise to 800B (10th percentile),
  gradual rise to 5000B (30th percentile), concave ramp to 16384B (100th)
- Phase 7.2 should capture real Chrome pcap data and refine the CDF
- Statistical validation uses KS test against this empirical CDF

## Sources
- HTTP/2 RFC 9113 (max frame size 16384)
- Chromium source code (SETTINGS values)
- Downey (2001): "Evidence for long-tailed distributions in the internet"
- LHS Nancy HTTP/2 traffic dataset (unavailable)
