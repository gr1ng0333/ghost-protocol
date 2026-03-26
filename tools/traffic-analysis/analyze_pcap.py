#!/usr/bin/env python3
"""
Ghost Traffic Analysis Toolkit — analyze_pcap.py

Analyzes packet capture files to characterize traffic patterns and
statistically compare Ghost VPN traffic against real Chrome traffic.

Usage:
  # Single pcap analysis:
  python3 analyze_pcap.py --pcap ghost.pcap --server-ip 94.156.122.66

  # Compare Ghost vs Chrome:
  python3 analyze_pcap.py --ghost ghost.pcap --chrome chrome.pcap \\
      --server-ip 94.156.122.66 --output-dir ./results/

  # With ML classification:
  python3 analyze_pcap.py --ghost ghost.pcap --chrome chrome.pcap \\
      --server-ip 94.156.122.66 --classify

Dependencies:
  pip install scapy scipy numpy matplotlib scikit-learn
"""

import argparse
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

# Lazy imports for optional heavy dependencies
_scapy_loaded = False
_scipy_loaded = False
_matplotlib_loaded = False
_sklearn_loaded = False


def _import_scapy():
    global _scapy_loaded
    if not _scapy_loaded:
        # Suppress scapy warnings
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        _scapy_loaded = True
    from scapy.all import rdpcap, IP, TCP
    return rdpcap, IP, TCP


def _import_scipy():
    global _scipy_loaded
    if not _scipy_loaded:
        _scipy_loaded = True
    from scipy.stats import ks_2samp
    return ks_2samp


def _import_matplotlib():
    global _matplotlib_loaded
    if not _matplotlib_loaded:
        import matplotlib
        matplotlib.use("Agg")
        _matplotlib_loaded = True
    import matplotlib.pyplot as plt
    return plt


def _import_sklearn():
    global _sklearn_loaded
    if not _sklearn_loaded:
        _sklearn_loaded = True
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_predict, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        confusion_matrix,
    )
    return (
        RandomForestClassifier,
        cross_val_predict,
        StratifiedKFold,
        accuracy_score,
        precision_score,
        recall_score,
        confusion_matrix,
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PacketInfo:
    timestamp: float
    size: int
    direction: str  # "c2s" (client→server) or "s2c" (server→client)
    tcp_flags: str


@dataclass
class FlowStats:
    """Statistics for one direction of traffic."""
    sizes: list = field(default_factory=list)
    timings: list = field(default_factory=list)  # inter-packet gaps (seconds)
    bursts: list = field(default_factory=list)  # burst sizes (packet count)
    idle_periods: list = field(default_factory=list)  # gaps > 500ms


@dataclass
class FlowFeatures:
    """Per-flow feature vector for ML classification."""
    mean_size: float = 0.0
    std_size: float = 0.0
    mean_timing: float = 0.0
    std_timing: float = 0.0
    burst_count: int = 0
    idle_count: int = 0
    total_bytes: int = 0
    duration: float = 0.0


# ---------------------------------------------------------------------------
# Pcap reading
# ---------------------------------------------------------------------------

def read_pcap(filepath: str, server_ip: str, client_ip: str | None = None) -> list[PacketInfo]:
    """Read a pcap file and extract per-packet metadata."""
    rdpcap, IP, TCP = _import_scapy()

    packets = rdpcap(filepath)
    results = []

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Determine direction
        if ip_layer.dst == server_ip:
            direction = "c2s"
            if client_ip and ip_layer.src != client_ip:
                continue
        elif ip_layer.src == server_ip:
            direction = "s2c"
            if client_ip and ip_layer.dst != client_ip:
                continue
        else:
            continue

        # TCP flags as string
        flags = str(tcp_layer.flags)

        results.append(PacketInfo(
            timestamp=float(pkt.time),
            size=len(pkt),
            direction=direction,
            tcp_flags=flags,
        ))

    results.sort(key=lambda p: p.timestamp)
    return results


# ---------------------------------------------------------------------------
# Statistics computation
# ---------------------------------------------------------------------------

BURST_GAP_THRESHOLD = 0.010   # 10ms — packets closer than this form a burst
IDLE_THRESHOLD = 0.500        # 500ms — gaps longer than this are idle periods


def compute_stats(packets: list[PacketInfo], direction: str) -> FlowStats:
    """Compute distributions for packets in one direction."""
    directed = [p for p in packets if p.direction == direction]
    if not directed:
        return FlowStats()

    stats = FlowStats()
    stats.sizes = [p.size for p in directed]

    # Inter-packet timing
    for i in range(1, len(directed)):
        gap = directed[i].timestamp - directed[i - 1].timestamp
        stats.timings.append(gap)

    # Burst detection
    burst_len = 1
    for gap in stats.timings:
        if gap < BURST_GAP_THRESHOLD:
            burst_len += 1
        else:
            stats.bursts.append(burst_len)
            burst_len = 1
            if gap > IDLE_THRESHOLD:
                stats.idle_periods.append(gap)
    stats.bursts.append(burst_len)  # last burst

    return stats


def summarize(arr: list | np.ndarray, label: str) -> str:
    """Return a one-line statistical summary."""
    if len(arr) == 0:
        return f"  {label}: no data"
    a = np.array(arr, dtype=float)
    return (
        f"  {label}: n={len(a)}, mean={a.mean():.4f}, std={a.std():.4f}, "
        f"median={np.median(a):.4f}, p5={np.percentile(a, 5):.4f}, "
        f"p95={np.percentile(a, 95):.4f}"
    )


def print_flow_stats(stats: FlowStats, direction_label: str) -> None:
    print(f"\n=== {direction_label} ===")
    print(summarize(stats.sizes, "Packet sizes (bytes)"))
    print(summarize(stats.timings, "Inter-packet timing (s)"))
    print(summarize(stats.bursts, "Burst sizes (packets)"))
    print(summarize(stats.idle_periods, "Idle periods (s)"))


# ---------------------------------------------------------------------------
# Statistical comparison (KS tests)
# ---------------------------------------------------------------------------

def ks_compare(a: list, b: list, label: str) -> tuple[float, float]:
    """Run KS test and print result. Returns (statistic, p-value)."""
    ks_2samp = _import_scipy()
    if len(a) < 2 or len(b) < 2:
        print(f"  {label}: insufficient data (ghost={len(a)}, chrome={len(b)})")
        return (float("nan"), float("nan"))

    stat, pvalue = ks_2samp(a, b)
    verdict = "NOT distinguishable" if pvalue > 0.05 else "DISTINGUISHABLE"
    print(f"  {label}: KS stat={stat:.4f}, p-value={pvalue:.6f} → {verdict}")
    return (stat, pvalue)


def compare_flows(ghost_stats: FlowStats, chrome_stats: FlowStats, label: str) -> dict:
    """Compare two FlowStats via KS tests. Returns dict of results."""
    print(f"\n=== KS Tests: {label} ===")
    results = {}
    results["size"] = ks_compare(ghost_stats.sizes, chrome_stats.sizes, "Packet size")
    results["timing"] = ks_compare(ghost_stats.timings, chrome_stats.timings, "Inter-packet timing")
    results["burst"] = ks_compare(ghost_stats.bursts, chrome_stats.bursts, "Burst size")
    return results


# ---------------------------------------------------------------------------
# Feature extraction for ML
# ---------------------------------------------------------------------------

def extract_features(packets: list[PacketInfo]) -> FlowFeatures:
    """Extract per-flow features for classification."""
    if not packets:
        return FlowFeatures()

    sizes = [p.size for p in packets]
    timings = []
    for i in range(1, len(packets)):
        timings.append(packets[i].timestamp - packets[i - 1].timestamp)

    # Burst / idle counting
    burst_count = 0
    idle_count = 0
    in_burst = True
    for gap in timings:
        if gap < BURST_GAP_THRESHOLD:
            if not in_burst:
                burst_count += 1
                in_burst = True
        else:
            in_burst = False
            if gap > IDLE_THRESHOLD:
                idle_count += 1
    if in_burst:
        burst_count += 1

    sa = np.array(sizes, dtype=float)
    ta = np.array(timings, dtype=float) if timings else np.array([0.0])

    duration = packets[-1].timestamp - packets[0].timestamp if len(packets) > 1 else 0.0

    return FlowFeatures(
        mean_size=sa.mean(),
        std_size=sa.std(),
        mean_timing=ta.mean(),
        std_timing=ta.std(),
        burst_count=burst_count,
        idle_count=idle_count,
        total_bytes=int(sa.sum()),
        duration=duration,
    )


# ---------------------------------------------------------------------------
# ML Classification
# ---------------------------------------------------------------------------

def segment_flows(packets: list[PacketInfo], window: float = 10.0) -> list[list[PacketInfo]]:
    """Segment a packet list into fixed-duration windows for training."""
    if not packets:
        return []
    flows = []
    start = packets[0].timestamp
    current_flow: list[PacketInfo] = []
    for p in packets:
        if p.timestamp - start > window:
            if len(current_flow) >= 10:  # need minimum packets
                flows.append(current_flow)
            current_flow = []
            start = p.timestamp
        current_flow.append(p)
    if len(current_flow) >= 10:
        flows.append(current_flow)
    return flows


def classify(ghost_packets: list[PacketInfo], chrome_packets: list[PacketInfo]) -> dict:
    """Train RF classifier on Ghost vs Chrome traffic windows."""
    (
        RandomForestClassifier,
        cross_val_predict,
        StratifiedKFold,
        accuracy_score,
        precision_score,
        recall_score,
        confusion_matrix,
    ) = _import_sklearn()

    ghost_flows = segment_flows(ghost_packets, window=10.0)
    chrome_flows = segment_flows(chrome_packets, window=10.0)

    if len(ghost_flows) < 5 or len(chrome_flows) < 5:
        print("\n=== ML Classification ===")
        print(f"  Insufficient flow windows: ghost={len(ghost_flows)}, chrome={len(chrome_flows)}")
        print("  Need at least 5 windows per class for 5-fold CV.")
        return {"error": "insufficient data"}

    X = []
    y = []
    for flow in ghost_flows:
        f = extract_features(flow)
        X.append([f.mean_size, f.std_size, f.mean_timing, f.std_timing,
                   f.burst_count, f.idle_count, f.total_bytes, f.duration])
        y.append(0)  # ghost
    for flow in chrome_flows:
        f = extract_features(flow)
        X.append([f.mean_size, f.std_size, f.mean_timing, f.std_timing,
                   f.burst_count, f.idle_count, f.total_bytes, f.duration])
        y.append(1)  # chrome

    X = np.array(X)
    y = np.array(y)

    n_splits = min(5, min(len(ghost_flows), len(chrome_flows)))
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    y_pred = cross_val_predict(clf, X, y, cv=cv)

    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    cm = confusion_matrix(y, y_pred)

    print("\n=== ML Classification (RandomForest, 5-fold CV) ===")
    print(f"  Ghost windows: {len(ghost_flows)}, Chrome windows: {len(chrome_flows)}")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  Confusion matrix (rows=true, cols=pred):")
    print(f"    Ghost→Ghost={cm[0][0]}  Ghost→Chrome={cm[0][1]}")
    print(f"    Chrome→Ghost={cm[1][0]}  Chrome→Chrome={cm[1][1]}")

    if acc <= 0.70:
        print("\n  ✓ VERDICT: Ghost is INDISTINGUISHABLE from Chrome (accuracy ≤ 70%)")
    elif acc <= 0.80:
        print("\n  ~ VERDICT: Marginal distinguishability (70% < accuracy ≤ 80%)")
    else:
        print("\n  ✗ VERDICT: Ghost has DISTINGUISHABLE patterns (accuracy > 80%) — NEEDS FIX")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "confusion_matrix": cm.tolist(),
        "ghost_windows": len(ghost_flows),
        "chrome_windows": len(chrome_flows),
    }


# ---------------------------------------------------------------------------
# Histogram generation
# ---------------------------------------------------------------------------

def save_histogram(data: list, label: str, xlabel: str, filepath: str) -> None:
    """Save a histogram PNG."""
    plt = _import_matplotlib()
    if len(data) == 0:
        return
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(data, bins=50, alpha=0.7, edgecolor="black")
    ax.set_title(label)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    fig.tight_layout()
    fig.savefig(filepath, dpi=100)
    plt.close(fig)
    print(f"  Saved: {filepath}")


def save_comparison_histogram(
    ghost_data: list, chrome_data: list, label: str, xlabel: str, filepath: str
) -> None:
    """Save overlaid histogram comparing Ghost vs Chrome."""
    plt = _import_matplotlib()
    if len(ghost_data) == 0 and len(chrome_data) == 0:
        return
    fig, ax = plt.subplots(figsize=(8, 4))
    if ghost_data:
        ax.hist(ghost_data, bins=50, alpha=0.5, label="Ghost", edgecolor="blue")
    if chrome_data:
        ax.hist(chrome_data, bins=50, alpha=0.5, label="Chrome", edgecolor="orange")
    ax.set_title(label)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    ax.legend()
    fig.tight_layout()
    fig.savefig(filepath, dpi=100)
    plt.close(fig)
    print(f"  Saved: {filepath}")


def generate_histograms(
    output_dir: str,
    ghost_c2s: FlowStats | None,
    ghost_s2c: FlowStats | None,
    chrome_c2s: FlowStats | None = None,
    chrome_s2c: FlowStats | None = None,
) -> None:
    """Generate all histogram PNGs."""
    os.makedirs(output_dir, exist_ok=True)
    print(f"\nGenerating histograms in {output_dir}/")

    if chrome_c2s is None:
        # Single-pcap mode
        if ghost_c2s:
            save_histogram(ghost_c2s.sizes, "Ghost C→S Packet Sizes", "Bytes",
                           os.path.join(output_dir, "ghost_c2s_sizes.png"))
            save_histogram(ghost_c2s.timings, "Ghost C→S Inter-Packet Timing", "Seconds",
                           os.path.join(output_dir, "ghost_c2s_timing.png"))
        if ghost_s2c:
            save_histogram(ghost_s2c.sizes, "Ghost S→C Packet Sizes", "Bytes",
                           os.path.join(output_dir, "ghost_s2c_sizes.png"))
            save_histogram(ghost_s2c.timings, "Ghost S→C Inter-Packet Timing", "Seconds",
                           os.path.join(output_dir, "ghost_s2c_timing.png"))
    else:
        # Comparison mode
        for direction, g_stats, c_stats, tag in [
            ("C→S", ghost_c2s, chrome_c2s, "c2s"),
            ("S→C", ghost_s2c, chrome_s2c, "s2c"),
        ]:
            if g_stats and c_stats:
                save_comparison_histogram(
                    g_stats.sizes, c_stats.sizes,
                    f"{direction} Packet Sizes: Ghost vs Chrome", "Bytes",
                    os.path.join(output_dir, f"compare_{tag}_sizes.png"),
                )
                save_comparison_histogram(
                    g_stats.timings, c_stats.timings,
                    f"{direction} Inter-Packet Timing: Ghost vs Chrome", "Seconds",
                    os.path.join(output_dir, f"compare_{tag}_timing.png"),
                )
                save_comparison_histogram(
                    g_stats.bursts, c_stats.bursts,
                    f"{direction} Burst Sizes: Ghost vs Chrome", "Packets",
                    os.path.join(output_dir, f"compare_{tag}_bursts.png"),
                )


# ---------------------------------------------------------------------------
# Pattern analysis (single pcap, no Chrome reference)
# ---------------------------------------------------------------------------

def analyze_patterns(packets: list[PacketInfo]) -> None:
    """Check Ghost traffic for suspicious patterns without a Chrome reference."""
    print("\n=== Pattern Analysis (heuristic checks) ===")

    sizes = [p.size for p in packets]
    if not sizes:
        print("  No packets to analyze.")
        return

    sa = np.array(sizes, dtype=float)

    # Check 1: Uniform distribution is suspicious
    # Real Chrome has clusters around specific sizes (TLS records ~16KB, small ACKs, etc.)
    # A high coefficient of variation with no clustering suggests natural traffic
    unique_ratio = len(set(sizes)) / len(sizes)
    print(f"  Unique size ratio: {unique_ratio:.4f} ({len(set(sizes))} unique / {len(sizes)} total)")
    if unique_ratio > 0.9:
        print("    → High diversity — looks natural (not fixed-size padding)")
    elif unique_ratio < 0.1:
        print("    → WARNING: Very low diversity — may indicate fixed-size padding")

    # Check 2: Timing periodicity
    timings = []
    for i in range(1, len(packets)):
        timings.append(packets[i].timestamp - packets[i - 1].timestamp)

    if len(timings) > 50:
        ta = np.array(timings)
        # Check for periodic peaks via autocorrelation
        centered = ta - ta.mean()
        if ta.std() > 0:
            autocorr = np.correlate(centered, centered, mode="full")
            autocorr = autocorr[len(autocorr) // 2:]
            autocorr /= autocorr[0] if autocorr[0] != 0 else 1
            # Look for secondary peaks above 0.3
            peaks = []
            for i in range(1, min(len(autocorr) - 1, 500)):
                if autocorr[i] > autocorr[i - 1] and autocorr[i] > autocorr[i + 1]:
                    if autocorr[i] > 0.3:
                        peaks.append((i, autocorr[i]))
            if peaks:
                print(f"    → WARNING: Timing autocorrelation peaks detected at lags: "
                      f"{', '.join(f'{lag}({val:.2f})' for lag, val in peaks[:5])}")
                print("    → This may indicate periodic shaping — real traffic is more irregular")
            else:
                print("    → No significant timing periodicity detected — good")
        else:
            print("    → Constant timing — suspicious")
    else:
        print("  (too few packets for periodicity analysis)")

    # Check 3: Burst/pause pattern
    c2s_stats = compute_stats(packets, "c2s")
    s2c_stats = compute_stats(packets, "s2c")
    total_bursts = len(c2s_stats.bursts) + len(s2c_stats.bursts)
    total_idles = len(c2s_stats.idle_periods) + len(s2c_stats.idle_periods)
    duration = packets[-1].timestamp - packets[0].timestamp if len(packets) > 1 else 0
    if duration > 0:
        bursts_per_sec = total_bursts / duration
        idles_per_sec = total_idles / duration
        print(f"  Burst rate: {bursts_per_sec:.2f}/s, Idle rate: {idles_per_sec:.2f}/s "
              f"over {duration:.1f}s")
        if bursts_per_sec > 10:
            print("    → High burst rate — consistent with active browsing")
        elif bursts_per_sec < 0.5:
            print("    → Very low burst rate — may look like a steady stream (suspicious)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ghost Traffic Analysis — compare Ghost VPN traffic against Chrome baseline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single Ghost pcap:
  %(prog)s --pcap ghost.pcap --server-ip 94.156.122.66

  # Compare Ghost vs Chrome:
  %(prog)s --ghost ghost.pcap --chrome chrome.pcap --server-ip 94.156.122.66

  # Full analysis with ML and histograms:
  %(prog)s --ghost ghost.pcap --chrome chrome.pcap --server-ip 94.156.122.66 \\
      --classify --output-dir ./analysis-results/
""",
    )
    p.add_argument("--pcap", help="Single pcap file to analyze")
    p.add_argument("--ghost", help="Ghost traffic pcap (comparison mode)")
    p.add_argument("--chrome", help="Chrome traffic pcap (comparison mode)")
    p.add_argument("--server-ip", required=True, help="Ghost/target server IP address")
    p.add_argument("--client-ip", help="Filter to specific client IP")
    p.add_argument("--classify", action="store_true", help="Train ML classifier (needs --ghost and --chrome)")
    p.add_argument("--output-dir", help="Directory for histogram PNGs")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Validate args
    if not args.pcap and not args.ghost:
        print("Error: provide --pcap (single analysis) or --ghost/--chrome (comparison)")
        sys.exit(1)

    if args.classify and (not args.ghost or not args.chrome):
        print("Error: --classify requires both --ghost and --chrome")
        sys.exit(1)

    # --- Single pcap mode ---
    if args.pcap:
        print(f"Reading {args.pcap}...")
        packets = read_pcap(args.pcap, args.server_ip, args.client_ip)
        print(f"  Total TCP packets (filtered): {len(packets)}")

        if not packets:
            print("No matching packets found. Check --server-ip and --client-ip filters.")
            sys.exit(1)

        c2s = compute_stats(packets, "c2s")
        s2c = compute_stats(packets, "s2c")
        print_flow_stats(c2s, "Client → Server")
        print_flow_stats(s2c, "Server → Client")

        features = extract_features(packets)
        print(f"\n=== Flow Features ===")
        print(f"  Total bytes: {features.total_bytes}")
        print(f"  Duration: {features.duration:.2f}s")
        print(f"  Mean size: {features.mean_size:.1f} ± {features.std_size:.1f}")
        print(f"  Mean timing: {features.mean_timing:.6f}s ± {features.std_timing:.6f}s")
        print(f"  Bursts: {features.burst_count}, Idle periods: {features.idle_count}")

        analyze_patterns(packets)

        if args.output_dir:
            generate_histograms(args.output_dir, c2s, s2c)

        return

    # --- Comparison mode ---
    print(f"Reading Ghost pcap: {args.ghost}...")
    ghost_packets = read_pcap(args.ghost, args.server_ip, args.client_ip)
    print(f"  Ghost packets: {len(ghost_packets)}")

    print(f"Reading Chrome pcap: {args.chrome}...")
    chrome_packets = read_pcap(args.chrome, args.server_ip, args.client_ip)
    print(f"  Chrome packets: {len(chrome_packets)}")

    if not ghost_packets:
        print("No Ghost packets found. Check filters.")
        sys.exit(1)
    if not chrome_packets:
        print("No Chrome packets found. Check filters.")
        sys.exit(1)

    # Stats for each
    ghost_c2s = compute_stats(ghost_packets, "c2s")
    ghost_s2c = compute_stats(ghost_packets, "s2c")
    chrome_c2s = compute_stats(chrome_packets, "c2s")
    chrome_s2c = compute_stats(chrome_packets, "s2c")

    print("\n--- Ghost Traffic ---")
    print_flow_stats(ghost_c2s, "Ghost Client → Server")
    print_flow_stats(ghost_s2c, "Ghost Server → Client")

    print("\n--- Chrome Traffic ---")
    print_flow_stats(chrome_c2s, "Chrome Client → Server")
    print_flow_stats(chrome_s2c, "Chrome Server → Client")

    # KS tests
    ks_c2s = compare_flows(ghost_c2s, chrome_c2s, "Client → Server")
    ks_s2c = compare_flows(ghost_s2c, chrome_s2c, "Server → Client")

    # Overall verdict
    print("\n=== Overall Statistical Verdict ===")
    all_pvalues = []
    for results in [ks_c2s, ks_s2c]:
        for key, (stat, pval) in results.items():
            if not np.isnan(pval):
                all_pvalues.append(pval)

    if all_pvalues:
        min_p = min(all_pvalues)
        distinguishable_count = sum(1 for p in all_pvalues if p <= 0.05)
        print(f"  Tests run: {len(all_pvalues)}, Distinguishable: {distinguishable_count}")
        print(f"  Min p-value: {min_p:.6f}")
        if distinguishable_count == 0:
            print("  ✓ VERDICT: Ghost traffic is NOT statistically distinguishable from Chrome")
        elif distinguishable_count <= len(all_pvalues) // 2:
            print("  ~ VERDICT: Partially distinguishable — some metrics differ")
        else:
            print("  ✗ VERDICT: Ghost traffic IS statistically distinguishable — NEEDS TUNING")

    # Pattern analysis on Ghost
    analyze_patterns(ghost_packets)

    # ML classification
    if args.classify:
        classify(ghost_packets, chrome_packets)

    # Histograms
    if args.output_dir:
        generate_histograms(args.output_dir, ghost_c2s, ghost_s2c, chrome_c2s, chrome_s2c)


if __name__ == "__main__":
    main()
