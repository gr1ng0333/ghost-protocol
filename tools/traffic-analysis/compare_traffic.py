#!/usr/bin/env python3
"""
Quick comparison of Ghost VPN and Chrome TLS traffic characteristics.

Uses tshark for fast extraction, then computes KS statistics.
Handles Chrome pcaps with traffic to multiple servers.

Usage:
  python compare_traffic.py \
    --ghost C:\tmp\ghost-stealth.pcap \
    --chrome C:\tmp\chrome-capture.pcap \
    --ghost-server-ip 94.156.122.66
"""

import argparse
import csv
import io
import os
import subprocess
import sys
import tempfile

import numpy as np

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def run_tshark(pcap, display_filter, fields):
    """Run tshark and return rows as list of lists."""
    cmd = [
        TSHARK, "-r", pcap,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
    ]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"tshark error: {result.stderr[:500]}", file=sys.stderr)
        return []

    rows = []
    for line in result.stdout.strip().split("\n"):
        if line:
            rows.append(line.split(","))
    return rows


def extract_tls_sizes(pcap, display_filter=None):
    """Extract TLS record sizes and packet sizes."""
    # Get TCP payload sizes and timestamps for TLS traffic
    filt = "tcp.port == 443 and tcp.len > 0"
    if display_filter:
        filt = f"{filt} and ({display_filter})"

    rows = run_tshark(pcap, filt, [
        "frame.time_epoch",
        "tcp.len",
        "frame.len",
        "ip.src",
        "ip.dst",
    ])

    timestamps = []
    tcp_sizes = []
    frame_sizes = []
    for row in rows:
        if len(row) >= 3:
            try:
                ts = float(row[0].strip('"'))
                tcp_sz = int(row[1].strip('"'))
                frm_sz = int(row[2].strip('"'))
                timestamps.append(ts)
                tcp_sizes.append(tcp_sz)
                frame_sizes.append(frm_sz)
            except (ValueError, IndexError):
                continue

    return np.array(timestamps), np.array(tcp_sizes), np.array(frame_sizes)


def compute_metrics(timestamps, tcp_sizes, frame_sizes, label=""):
    """Compute traffic metrics from extracted data."""
    if len(timestamps) == 0:
        print(f"  [{label}] No packets found!")
        return {}

    # Sort by time
    order = np.argsort(timestamps)
    ts = timestamps[order]
    tcp = tcp_sizes[order]
    frames = frame_sizes[order]

    # Inter-packet timing
    ipt = np.diff(ts)
    ipt = ipt[ipt >= 0]  # Filter negative (reordering)

    # Burst detection (packets within 10ms)
    burst_sizes = []
    burst = 1
    for gap in ipt:
        if gap < 0.010:
            burst += 1
        else:
            burst_sizes.append(burst)
            burst = 1
    burst_sizes.append(burst)

    duration = ts[-1] - ts[0] if len(ts) > 1 else 0

    metrics = {
        "n_packets": len(tcp),
        "duration_s": duration,
        "tcp_sizes": tcp,
        "frame_sizes": frames,
        "ipt": ipt,
        "burst_sizes": np.array(burst_sizes),
        "mean_tcp_size": np.mean(tcp),
        "median_tcp_size": np.median(tcp),
        "std_tcp_size": np.std(tcp),
        "p5_tcp_size": np.percentile(tcp, 5),
        "p95_tcp_size": np.percentile(tcp, 95),
        "mean_ipt": np.mean(ipt) if len(ipt) > 0 else 0,
        "median_ipt": np.median(ipt) if len(ipt) > 0 else 0,
        "mean_burst": np.mean(burst_sizes),
        "median_burst": np.median(burst_sizes),
    }

    print(f"\n=== {label} ===")
    print(f"  Packets with data: {len(tcp)}")
    print(f"  Duration: {duration:.1f}s")
    print(f"  TCP payload sizes: mean={np.mean(tcp):.0f}, median={np.median(tcp):.0f}, "
          f"std={np.std(tcp):.0f}, p5={np.percentile(tcp,5):.0f}, p95={np.percentile(tcp,95):.0f}")
    print(f"  Frame sizes: mean={np.mean(frames):.0f}, median={np.median(frames):.0f}, "
          f"std={np.std(frames):.0f}")
    if len(ipt) > 0:
        print(f"  Inter-packet timing (ms): mean={np.mean(ipt)*1000:.1f}, "
              f"median={np.median(ipt)*1000:.1f}, p5={np.percentile(ipt,5)*1000:.3f}, "
              f"p95={np.percentile(ipt,95)*1000:.1f}")
    print(f"  Burst sizes: mean={np.mean(burst_sizes):.1f}, median={np.median(burst_sizes):.0f}, "
          f"max={max(burst_sizes)}")

    return metrics


def ks_compare(a, b, name):
    """Run KS test between two distributions."""
    from scipy.stats import ks_2samp
    if len(a) < 5 or len(b) < 5:
        return None, None
    stat, pval = ks_2samp(a, b)
    verdict = "SAME" if pval > 0.05 else "DIFFERENT"
    print(f"  {name}: KS stat={stat:.4f}, p-value={pval:.6f} → {verdict}")
    return stat, pval


def classify_ml(ghost_metrics, chrome_metrics):
    """Train Random Forest classifier to distinguish Ghost from Chrome."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    def make_windows(tcp_sizes, ipt, burst_sizes, window=50):
        """Create feature vectors from sliding windows."""
        features = []
        n = len(tcp_sizes)
        for i in range(0, n - window, window // 2):
            w_sizes = tcp_sizes[i:i+window]
            w_ipt = ipt[i:min(i+window-1, len(ipt))]
            w_bursts = burst_sizes[i//max(1,len(burst_sizes)//max(1,n//window)):
                                   (i+window)//max(1,len(burst_sizes)//max(1,n//window))]

            feat = [
                np.mean(w_sizes), np.std(w_sizes), np.median(w_sizes),
                np.percentile(w_sizes, 25), np.percentile(w_sizes, 75),
            ]
            if len(w_ipt) > 0:
                feat += [np.mean(w_ipt), np.std(w_ipt), np.median(w_ipt)]
            else:
                feat += [0, 0, 0]
            features.append(feat)
        return features

    ghost_features = make_windows(ghost_metrics["tcp_sizes"],
                                   ghost_metrics["ipt"],
                                   ghost_metrics["burst_sizes"])
    chrome_features = make_windows(chrome_metrics["tcp_sizes"],
                                    chrome_metrics["ipt"],
                                    chrome_metrics["burst_sizes"])

    if len(ghost_features) < 5 or len(chrome_features) < 5:
        print("  Not enough data windows for ML classification")
        return None

    # Balance datasets
    n = min(len(ghost_features), len(chrome_features))
    X = np.array(ghost_features[:n] + chrome_features[:n])
    y = np.array([0]*n + [1]*n)  # 0=Ghost, 1=Chrome

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    scores = cross_val_score(clf, X, y, cv=min(5, n), scoring="accuracy")

    mean_acc = np.mean(scores)
    print(f"\n=== ML Classification (Random Forest) ===")
    print(f"  Samples: {n} Ghost, {n} Chrome ({n*2} total)")
    print(f"  Cross-val accuracy: {mean_acc:.1%} ± {np.std(scores):.1%}")
    if mean_acc < 0.60:
        print(f"  → GOOD: Classifier cannot reliably distinguish Ghost from Chrome")
    elif mean_acc < 0.75:
        print(f"  → WARNING: Partially distinguishable ({mean_acc:.0%})")
    else:
        print(f"  → ALERT: Highly distinguishable ({mean_acc:.0%}) — shaping needs work")

    return mean_acc


def main():
    parser = argparse.ArgumentParser(description="Compare Ghost vs Chrome traffic")
    parser.add_argument("--ghost", required=True, help="Ghost pcap file")
    parser.add_argument("--chrome", required=True, help="Chrome pcap file")
    parser.add_argument("--ghost-server-ip", required=True, help="Ghost server IP")
    parser.add_argument("--classify", action="store_true", help="Run ML classifier")
    args = parser.parse_args()

    print("=" * 60)
    print("Ghost vs Chrome Traffic Comparison")
    print("=" * 60)

    # Extract Ghost traffic (filtered to server IP)
    ghost_filter = f"ip.addr == {args.ghost_server_ip}"
    print(f"\nExtracting Ghost traffic (filter: {ghost_filter})...")
    g_ts, g_tcp, g_frames = extract_tls_sizes(args.ghost, ghost_filter)
    ghost_m = compute_metrics(g_ts, g_tcp, g_frames, "Ghost (stealth)")

    # Extract Chrome traffic (all HTTPS)
    print(f"\nExtracting Chrome traffic (all HTTPS)...")
    c_ts, c_tcp, c_frames = extract_tls_sizes(args.chrome)
    chrome_m = compute_metrics(c_ts, c_tcp, c_frames, "Chrome (real)")

    if not ghost_m or not chrome_m:
        print("Not enough data for comparison")
        return

    # KS tests
    print("\n=== Kolmogorov-Smirnov Tests ===")
    results = {}
    results["tcp_sizes"] = ks_compare(ghost_m["tcp_sizes"], chrome_m["tcp_sizes"],
                                       "TCP payload sizes")
    results["frame_sizes"] = ks_compare(ghost_m["frame_sizes"], chrome_m["frame_sizes"],
                                         "Frame sizes")
    if len(ghost_m["ipt"]) > 0 and len(chrome_m["ipt"]) > 0:
        results["ipt"] = ks_compare(ghost_m["ipt"], chrome_m["ipt"],
                                     "Inter-packet timing")
    results["bursts"] = ks_compare(ghost_m["burst_sizes"], chrome_m["burst_sizes"],
                                    "Burst sizes")

    # Overall verdict
    print("\n=== OVERALL VERDICT ===")
    pvals = [v[1] for v in results.values() if v[1] is not None]
    if pvals:
        distinguishable = sum(1 for p in pvals if p <= 0.05)
        print(f"  Tests: {len(pvals)}, Distinguishable: {distinguishable}/{len(pvals)}")
        print(f"  P-values: {', '.join(f'{p:.6f}' for p in pvals)}")
        if distinguishable == 0:
            print("  ✓ Ghost traffic is NOT statistically distinguishable from Chrome")
        elif distinguishable <= len(pvals) // 2:
            print("  ~ Partially distinguishable — some metrics differ")
        else:
            print("  ✗ Ghost traffic IS statistically distinguishable")

    # ML
    if args.classify:
        classify_ml(ghost_m, chrome_m)

    # Summary table
    print("\n=== COMPARISON TABLE ===")
    print(f"{'Metric':<30} {'Ghost':>12} {'Chrome':>12} {'KS p-value':>12}")
    print("-" * 68)
    print(f"{'Packets':<30} {ghost_m['n_packets']:>12d} {chrome_m['n_packets']:>12d} {'':>12}")
    print(f"{'Duration (s)':<30} {ghost_m['duration_s']:>12.1f} {chrome_m['duration_s']:>12.1f} {'':>12}")
    print(f"{'Mean TCP size':<30} {ghost_m['mean_tcp_size']:>12.0f} {chrome_m['mean_tcp_size']:>12.0f} "
          f"{results.get('tcp_sizes',(None,None))[1]:>12.6f}" if results.get('tcp_sizes',(None,None))[1] else "")
    print(f"{'Median TCP size':<30} {ghost_m['median_tcp_size']:>12.0f} {chrome_m['median_tcp_size']:>12.0f} {'':>12}")
    print(f"{'P95 TCP size':<30} {ghost_m['p95_tcp_size']:>12.0f} {chrome_m['p95_tcp_size']:>12.0f} {'':>12}")
    print(f"{'Mean IPT (ms)':<30} {ghost_m['mean_ipt']*1000:>12.1f} {chrome_m['mean_ipt']*1000:>12.1f} "
          f"{results.get('ipt',(None,None))[1]:>12.6f}" if results.get('ipt',(None,None))[1] else "")
    print(f"{'Median IPT (ms)':<30} {ghost_m['median_ipt']*1000:>12.1f} {chrome_m['median_ipt']*1000:>12.1f} {'':>12}")
    print(f"{'Mean burst size':<30} {ghost_m['mean_burst']:>12.1f} {chrome_m['mean_burst']:>12.1f} "
          f"{results.get('bursts',(None,None))[1]:>12.6f}" if results.get('bursts',(None,None))[1] else "")


if __name__ == "__main__":
    main()
