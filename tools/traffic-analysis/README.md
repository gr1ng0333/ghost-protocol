# Ghost Traffic Analysis Toolkit

Tools for capturing and statistically analyzing Ghost VPN traffic patterns,
comparing them against real Chrome HTTPS traffic to assess whether Ghost
is distinguishable by deep packet inspection.

## Overview

| Tool | Purpose | Runs on |
|------|---------|---------|
| `analyze_pcap.py` | Statistical analysis of pcap files | Local machine |
| `capture_ghost.sh` | Capture Ghost client traffic | VPS |
| `capture_chrome.sh` | Capture Chrome reference traffic | VPS |

## Prerequisites

### Local (for analysis)

```bash
pip install scapy scipy numpy matplotlib scikit-learn
```

### VPS (for capture)

```bash
# tcpdump is usually pre-installed; if not:
apt-get install -y tcpdump
```

## Quick Start

### 1. Upload capture scripts to VPS

```bash
scp tools/traffic-analysis/capture_ghost.sh root@94.156.122.66:/tmp/
scp tools/traffic-analysis/capture_chrome.sh root@94.156.122.66:/tmp/
ssh root@94.156.122.66 "chmod +x /tmp/capture_*.sh"
```

### 2. Capture Ghost traffic (2 minutes)

**Terminal 1 (SSH to VPS):**
```bash
ssh root@94.156.122.66 "/tmp/capture_ghost.sh 120 /tmp/ghost-session.pcap"
```

**Terminal 2 (local — start Ghost client and browse):**
```bash
# Start Ghost client if not running:
ghost-client -config configs/client-production.yaml

# Browse through the SOCKS5 proxy:
curl --socks5 127.0.0.1:1080 https://www.google.com/
curl --socks5 127.0.0.1:1080 https://www.wikipedia.org/
# Or set browser SOCKS5 proxy to 127.0.0.1:1080 and browse normally
```

### 3. Capture Chrome reference traffic (2 minutes)

**Terminal 1 (SSH to VPS):**
```bash
ssh root@94.156.122.66 "/tmp/capture_chrome.sh 120 /tmp/chrome-session.pcap"
```

**Terminal 2 (local — use Chrome):**
Open Chrome and visit `https://397841.vm.spacecore.network/` .
Click around, refresh pages, browse for 2 minutes.

### 4. Retrieve pcap files

```bash
scp root@94.156.122.66:/tmp/ghost-session.pcap /tmp/
scp root@94.156.122.66:/tmp/chrome-session.pcap /tmp/
```

### 5. Run analysis

```bash
# Single pcap analysis (Ghost only):
python3 tools/traffic-analysis/analyze_pcap.py \
  --pcap /tmp/ghost-session.pcap \
  --server-ip 94.156.122.66

# Comparison mode (Ghost vs Chrome):
python3 tools/traffic-analysis/analyze_pcap.py \
  --ghost /tmp/ghost-session.pcap \
  --chrome /tmp/chrome-session.pcap \
  --server-ip 94.156.122.66 \
  --output-dir ./analysis-results/

# Full analysis with ML classifier:
python3 tools/traffic-analysis/analyze_pcap.py \
  --ghost /tmp/ghost-session.pcap \
  --chrome /tmp/chrome-session.pcap \
  --server-ip 94.156.122.66 \
  --classify \
  --output-dir ./analysis-results/
```

## Analysis Output

### Single pcap mode (`--pcap`)

- Packet size distribution (mean, std, median, p5, p95) per direction
- Inter-packet timing distribution
- Burst detection (consecutive packets with <10ms gap)
- Idle period distribution (gaps >500ms)
- Pattern heuristics: size diversity, timing periodicity, burst/pause rates

### Comparison mode (`--ghost` + `--chrome`)

All single-pcap statistics, plus:
- **KS tests** on packet size, timing, and burst distributions
  - p > 0.05 → "not statistically distinguishable"
  - p ≤ 0.05 → "distinguishable"
- Overall verdict across all tests

### ML classification (`--classify`)

- Segments traffic into 10-second flow windows
- Extracts features: mean/std size, mean/std timing, burst count, idle count, total bytes, duration
- Trains RandomForest with 5-fold stratified cross-validation
- Reports accuracy, precision, recall, confusion matrix
- **Accuracy ≤ 70%**: Ghost is indistinguishable ✓
- **Accuracy > 80%**: Ghost has detectable patterns ✗

### Histograms (`--output-dir`)

Generates PNG files:
- `ghost_{c2s,s2c}_{sizes,timing}.png` (single mode)
- `compare_{c2s,s2c}_{sizes,timing,bursts}.png` (comparison mode)

## Interpreting Results

| Metric | Good (stealth) | Bad (detectable) |
|--------|----------------|-------------------|
| KS p-value | > 0.05 | ≤ 0.05 |
| ML accuracy | ≤ 70% | > 80% |
| Size diversity | High unique ratio | Very low (fixed padding) |
| Timing periodicity | No autocorrelation peaks | Strong peaks |
| Burst rate | Similar to Chrome | Steady stream |
