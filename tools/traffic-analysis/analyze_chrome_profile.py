#!/usr/bin/env python3
"""Analyze Chrome TLS capture to extract real traffic patterns for Ghost profile.

Reads tshark-extracted CSV files:
  - C:/tmp/chrome-tls-records.csv  (TLS application data records)
  - C:/tmp/chrome-tcp-payload.csv  (TCP payload frames)

Produces:
  - Statistics and distributions for profile update
  - JSON-formatted CDF samples compatible with chrome_browsing.json
"""

import json
import math
import sys
from pathlib import Path

import numpy as np

# ─── Config ───
CLIENT_IP = "192.168.50.79"
SERVER_IP = "80.71.227.193"
TLS_RECORDS_FILE = Path("C:/tmp/chrome-tls-records.csv")
TCP_PAYLOAD_FILE = Path("C:/tmp/chrome-tcp-payload.csv")
CURRENT_PROFILE = Path(__file__).resolve().parent.parent.parent / "profiles" / "chrome_browsing.json"


def load_tls_records(path):
    """Load TLS record data: time, src, dst, lengths (may be comma-separated per frame)."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            try:
                time_rel = float(parts[0])
            except ValueError:
                continue
            src = parts[1]
            dst = parts[2]
            # TLS record lengths may be comma-separated (multiple records per frame)
            length_str = parts[3]
            for ls in length_str.split(","):
                ls = ls.strip()
                if ls:
                    try:
                        records.append({
                            "time": time_rel,
                            "src": src,
                            "dst": dst,
                            "length": int(ls),
                        })
                    except ValueError:
                        pass
    return records


def load_tcp_payload(path):
    """Load TCP payload data: time, src, dst, srcport, dstport, tcp_len, frame_len."""
    frames = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            try:
                frames.append({
                    "time": float(parts[0]),
                    "src": parts[1],
                    "dst": parts[2],
                    "srcport": int(parts[3]),
                    "dstport": int(parts[4]),
                    "tcp_len": int(parts[5]),
                    "frame_len": int(parts[6]) if len(parts) > 6 else 0,
                })
            except (ValueError, IndexError):
                pass
    return frames


def compute_stats(values, label=""):
    """Compute descriptive statistics for an array of values."""
    arr = np.array(values, dtype=float)
    if len(arr) == 0:
        return {"count": 0}
    return {
        "label": label,
        "count": len(arr),
        "min": float(np.min(arr)),
        "p5": float(np.percentile(arr, 5)),
        "p25": float(np.percentile(arr, 25)),
        "median": float(np.median(arr)),
        "p75": float(np.percentile(arr, 75)),
        "p95": float(np.percentile(arr, 95)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
    }


def compute_cdf_samples(values, n_points=101):
    """Compute empirical CDF breakpoints (n_points evenly spaced percentiles)."""
    arr = np.array(values, dtype=float)
    percentiles = np.linspace(0, 100, n_points)
    return [round(float(np.percentile(arr, p))) for p in percentiles]


def compute_histogram(values, bin_width=50, max_val=None):
    """Compute histogram with specified bin width."""
    arr = np.array(values, dtype=float)
    if max_val is None:
        max_val = np.max(arr)
    bins = np.arange(0, max_val + bin_width, bin_width)
    counts, edges = np.histogram(arr, bins=bins)
    return [(int(edges[i]), int(edges[i + 1]), int(counts[i])) for i in range(len(counts)) if counts[i] > 0]


def analyze_timing(records, direction_filter=None):
    """Analyze inter-packet timing for records in a specific direction."""
    if direction_filter:
        filtered = [r for r in records if r["src"] == direction_filter]
    else:
        filtered = records

    if len(filtered) < 2:
        return {}

    sorted_recs = sorted(filtered, key=lambda r: r["time"])
    gaps = []
    for i in range(1, len(sorted_recs)):
        gap_ms = (sorted_recs[i]["time"] - sorted_recs[i - 1]["time"]) * 1000
        if gap_ms >= 0:
            gaps.append(gap_ms)

    if not gaps:
        return {}

    intra_burst = [g for g in gaps if g < 50]
    inter_burst = [g for g in gaps if g >= 50]

    result = {
        "all_gaps": compute_stats(gaps, "all inter-packet gaps (ms)"),
    }
    if intra_burst:
        result["intra_burst"] = compute_stats(intra_burst, "intra-burst gaps <50ms")
    if inter_burst:
        result["inter_burst"] = compute_stats(inter_burst, "inter-burst gaps >=50ms")

    return result


def analyze_bursts(records, gap_threshold_ms=10):
    """Analyze burst patterns: consecutive packets with <gap_threshold_ms gap."""
    sorted_recs = sorted(records, key=lambda r: r["time"])

    bursts = []
    current_burst = [sorted_recs[0]]

    for i in range(1, len(sorted_recs)):
        gap_ms = (sorted_recs[i]["time"] - sorted_recs[i - 1]["time"]) * 1000
        if gap_ms < gap_threshold_ms:
            current_burst.append(sorted_recs[i])
        else:
            if len(current_burst) > 0:
                bursts.append(current_burst)
            current_burst = [sorted_recs[i]]

    if current_burst:
        bursts.append(current_burst)

    burst_sizes = [len(b) for b in bursts]
    burst_volumes = [sum(r["length"] for r in b) for b in bursts]

    # Inter-burst pauses
    pauses = []
    for i in range(1, len(bursts)):
        pause = (bursts[i][0]["time"] - bursts[i - 1][-1]["time"]) * 1000
        pauses.append(pause)

    return {
        "num_bursts": len(bursts),
        "burst_size_stats": compute_stats(burst_sizes, "packets per burst"),
        "burst_volume_stats": compute_stats(burst_volumes, "bytes per burst"),
        "pause_stats": compute_stats(pauses, "inter-burst pause (ms)") if pauses else {},
    }


def fit_lognormal(values):
    """Fit lognormal parameters (mu, sigma) to positive values via log-transform."""
    arr = np.array([v for v in values if v > 0], dtype=float)
    if len(arr) < 2:
        return 0.0, 1.0
    log_vals = np.log(arr)
    mu = float(np.mean(log_vals))
    sigma = float(np.std(log_vals))
    return mu, sigma


def format_stats(stats):
    """Format statistics dict as readable string."""
    if not stats or stats.get("count", 0) == 0:
        return "  (no data)"
    lines = []
    label = stats.get("label", "")
    if label:
        lines.append(f"  {label}")
    lines.append(f"  count={stats['count']:,}")
    lines.append(f"  min={stats['min']:.1f}  p5={stats['p5']:.1f}  p25={stats['p25']:.1f}  "
                 f"median={stats['median']:.1f}  p75={stats['p75']:.1f}  p95={stats['p95']:.1f}  "
                 f"max={stats['max']:.1f}")
    lines.append(f"  mean={stats['mean']:.1f}  std={stats['std']:.1f}")
    return "\n".join(lines)


def main():
    print("=" * 70)
    print("Chrome Traffic Profile Analysis")
    print("=" * 70)

    # ─── Load data ───
    tls_records = load_tls_records(TLS_RECORDS_FILE)
    tcp_frames = load_tcp_payload(TCP_PAYLOAD_FILE)

    print(f"\nLoaded {len(tls_records)} TLS records from {TLS_RECORDS_FILE}")
    print(f"Loaded {len(tcp_frames)} TCP payload frames from {TCP_PAYLOAD_FILE}")

    if not tls_records:
        print("ERROR: No TLS records found")
        sys.exit(1)

    # Compute capture duration
    times = [r["time"] for r in tls_records]
    duration = max(times) - min(times)
    print(f"Capture duration: {duration:.1f} seconds ({duration / 60:.1f} minutes)")

    # ─── 1. TLS Record Size Distribution ───
    print("\n" + "=" * 70)
    print("1. TLS RECORD SIZE DISTRIBUTION (what DPI sees)")
    print("=" * 70)

    all_tls_sizes = [r["length"] for r in tls_records]
    client_tls = [r["length"] for r in tls_records if r["src"] == CLIENT_IP]
    server_tls = [r["length"] for r in tls_records if r["src"] == SERVER_IP]

    print(f"\nAll TLS records:")
    print(format_stats(compute_stats(all_tls_sizes, "all directions")))
    print(f"\nClient → Server ({len(client_tls)} records):")
    print(format_stats(compute_stats(client_tls, "client→server")))
    print(f"\nServer → Client ({len(server_tls)} records):")
    print(format_stats(compute_stats(server_tls, "server→client")))

    # Histogram (50-byte bins)
    print("\nSize histogram (50-byte bins, top 20):")
    hist = compute_histogram(all_tls_sizes, bin_width=50)
    hist_sorted = sorted(hist, key=lambda x: x[2], reverse=True)[:20]
    for lo, hi, count in sorted(hist_sorted, key=lambda x: x[0]):
        pct = count / len(all_tls_sizes) * 100
        print(f"  {lo:6d}-{hi:6d}: {count:6d} ({pct:5.1f}%)")

    # ─── 2. TCP Payload Size Distribution ───
    print("\n" + "=" * 70)
    print("2. TCP PAYLOAD SIZE DISTRIBUTION")
    print("=" * 70)

    all_tcp_sizes = [f["tcp_len"] for f in tcp_frames]
    client_tcp = [f["tcp_len"] for f in tcp_frames if f["src"] == CLIENT_IP]
    server_tcp = [f["tcp_len"] for f in tcp_frames if f["src"] == SERVER_IP]

    print(f"\nAll TCP payloads:")
    print(format_stats(compute_stats(all_tcp_sizes, "all directions")))
    print(f"\nClient → Server ({len(client_tcp)} frames):")
    print(format_stats(compute_stats(client_tcp, "client→server")))
    print(f"\nServer → Client ({len(server_tcp)} frames):")
    print(format_stats(compute_stats(server_tcp, "server→client")))

    # ─── 3. Inter-packet Timing ───
    print("\n" + "=" * 70)
    print("3. INTER-PACKET TIMING DISTRIBUTION")
    print("=" * 70)

    timing_all = analyze_timing(tls_records)
    timing_client = analyze_timing(tls_records, CLIENT_IP)
    timing_server = analyze_timing(tls_records, SERVER_IP)

    print("\nAll directions:")
    for k, v in timing_all.items():
        print(format_stats(v))
    print("\nClient → Server:")
    for k, v in timing_client.items():
        print(format_stats(v))
    print("\nServer → Client:")
    for k, v in timing_server.items():
        print(format_stats(v))

    # Fit lognormal to all inter-packet gaps
    sorted_all = sorted(tls_records, key=lambda r: r["time"])
    all_gaps_ms = []
    for i in range(1, len(sorted_all)):
        gap_ms = (sorted_all[i]["time"] - sorted_all[i - 1]["time"]) * 1000
        if gap_ms > 0:
            all_gaps_ms.append(gap_ms)

    if all_gaps_ms:
        mu_timing, sigma_timing = fit_lognormal(all_gaps_ms)
        print(f"\nLognormal fit for inter-packet timing:")
        print(f"  mu={mu_timing:.4f}, sigma={sigma_timing:.4f}")
        print(f"  (median = e^mu = {math.exp(mu_timing):.1f} ms)")

    # ─── 4. Burst Analysis ───
    print("\n" + "=" * 70)
    print("4. BURST ANALYSIS (gap threshold = 10ms)")
    print("=" * 70)

    burst_results = analyze_bursts(tls_records, gap_threshold_ms=10)
    print(f"\nNumber of bursts: {burst_results['num_bursts']}")
    print("\nBurst size (packets per burst):")
    print(format_stats(burst_results["burst_size_stats"]))
    print("\nBurst volume (bytes per burst):")
    print(format_stats(burst_results["burst_volume_stats"]))
    print("\nInter-burst pause:")
    print(format_stats(burst_results.get("pause_stats", {})))

    # Also try with larger gap threshold for broader burst definition
    burst_50 = analyze_bursts(tls_records, gap_threshold_ms=50)
    print(f"\nBurst analysis with 50ms threshold:")
    print(f"  Number of bursts: {burst_50['num_bursts']}")
    print("  Burst size:", format_stats(burst_50["burst_size_stats"]).strip())
    print("  Burst volume:", format_stats(burst_50["burst_volume_stats"]).strip())
    print("  Pause:", format_stats(burst_50.get("pause_stats", {})).strip())

    # ─── 5. Session Pattern ───
    print("\n" + "=" * 70)
    print("5. SESSION PATTERN")
    print("=" * 70)

    # Group by connection (src_port for client, dst_port for server)
    connections = {}
    for f in tcp_frames:
        if f["src"] == CLIENT_IP:
            key = f["srcport"]
        else:
            key = f["dstport"]
        connections.setdefault(key, []).append(f)

    conn_durations = []
    conn_bytes_sent = []
    conn_bytes_recv = []
    for port, frames in connections.items():
        times_c = [f["time"] for f in frames]
        dur = max(times_c) - min(times_c) if len(times_c) > 1 else 0
        conn_durations.append(dur)
        sent = sum(f["tcp_len"] for f in frames if f["src"] == CLIENT_IP)
        recv = sum(f["tcp_len"] for f in frames if f["src"] == SERVER_IP)
        conn_bytes_sent.append(sent)
        conn_bytes_recv.append(recv)

    print(f"\nTotal connections: {len(connections)}")
    print(f"\nConnection duration (seconds):")
    print(format_stats(compute_stats(conn_durations, "duration")))
    print(f"\nBytes sent per connection (client→server):")
    print(format_stats(compute_stats(conn_bytes_sent, "bytes sent")))
    print(f"\nBytes received per connection (server→client):")
    print(format_stats(compute_stats(conn_bytes_recv, "bytes received")))

    # Active vs idle ratio
    active_time = 0
    for port, frames in connections.items():
        sorted_f = sorted(frames, key=lambda x: x["time"])
        for i in range(1, len(sorted_f)):
            gap = sorted_f[i]["time"] - sorted_f[i - 1]["time"]
            if gap < 1.0:  # Active if gap < 1 second
                active_time += gap
    idle_time = duration - active_time
    print(f"\nActive time: {active_time:.1f}s ({active_time / duration * 100:.1f}%)")
    print(f"Idle time: {idle_time:.1f}s ({idle_time / duration * 100:.1f}%)")

    # ─── 6. Generate Profile Data ───
    print("\n" + "=" * 70)
    print("6. GENERATED PROFILE DATA")
    print("=" * 70)

    # CDF samples for size distribution (101 points)
    # Use TLS record sizes as that's what the wire sees and Ghost shapes
    cdf_samples = compute_cdf_samples(all_tls_sizes, 101)
    print(f"\nEmpirical CDF (101 points) from TLS record sizes:")
    print(f"  Range: {cdf_samples[0]} - {cdf_samples[-1]}")
    print(f"  Samples: {cdf_samples}")

    # Timing distribution (lognormal fit)
    print(f"\nTiming distribution (lognormal):")
    print(f"  mu={mu_timing:.4f}, sigma={sigma_timing:.4f}")

    # Burst config from empirical data
    bv = burst_results["burst_volume_stats"]
    bp = burst_results.get("pause_stats", {})
    bs = burst_results["burst_size_stats"]

    min_burst = int(bv.get("p5", 1000)) if bv.get("count", 0) > 0 else 1000
    max_burst = int(bv.get("p95", 100000)) if bv.get("count", 0) > 0 else 100000
    min_pause = int(bp.get("p5", 50)) if bp.get("count", 0) > 0 else 50
    max_pause = int(bp.get("p95", 2000)) if bp.get("count", 0) > 0 else 2000
    min_count = int(bs.get("p5", 1)) if bs.get("count", 0) > 0 else 1
    max_count = int(bs.get("p95", 20)) if bs.get("count", 0) > 0 else 20

    print(f"\nBurst config (from p5-p95 range):")
    print(f"  min_burst_bytes: {min_burst}")
    print(f"  max_burst_bytes: {max_burst}")
    print(f"  min_pause_ms: {min_pause}")
    print(f"  max_pause_ms: {max_pause}")
    print(f"  burst_count: [{min_count}, {max_count}]")

    # ─── 7. Build new profile JSON ───
    new_profile = {
        "name": "chrome_browsing",
        "size_distribution": {
            "type": "empirical",
            "params": [],
            "samples": cdf_samples,
        },
        "timing_distribution": {
            "type": "lognormal",
            "params": [round(mu_timing, 2), round(sigma_timing, 2)],
        },
        "burst_config": {
            "min_burst_bytes": min_burst,
            "max_burst_bytes": max_burst,
            "min_pause_ms": min_pause,
            "max_pause_ms": max_pause,
            "burst_count_distribution": {
                "type": "uniform",
                "params": [min_count, max_count],
            },
        },
    }

    # Write new profile to temp for comparison
    new_json = json.dumps(new_profile, indent=2)
    output_path = Path("C:/tmp/chrome_browsing_new.json")
    output_path.write_text(new_json, encoding="utf-8")
    print(f"\nNew profile written to: {output_path}")

    # ─── 8. Compare with current profile ───
    print("\n" + "=" * 70)
    print("7. COMPARISON: OLD vs NEW PROFILE")
    print("=" * 70)

    current = json.loads(CURRENT_PROFILE.read_text(encoding="utf-8"))

    print("\nSize distribution samples:")
    old_samples = current["size_distribution"]["samples"]
    new_samples = new_profile["size_distribution"]["samples"]
    print(f"  OLD range: {old_samples[0]} - {old_samples[-1]} ({len(old_samples)} points)")
    print(f"  NEW range: {new_samples[0]} - {new_samples[-1]} ({len(new_samples)} points)")
    print(f"  OLD median (p50): {old_samples[50]}")
    print(f"  NEW median (p50): {new_samples[50]}")
    print(f"  OLD p25: {old_samples[25]}")
    print(f"  NEW p25: {new_samples[25]}")
    print(f"  OLD p75: {old_samples[75]}")
    print(f"  NEW p75: {new_samples[75]}")

    print("\nTiming distribution:")
    old_timing = current["timing_distribution"]["params"]
    new_timing = new_profile["timing_distribution"]["params"]
    print(f"  OLD: mu={old_timing[0]}, sigma={old_timing[1]}")
    print(f"  NEW: mu={new_timing[0]}, sigma={new_timing[1]}")
    print(f"  OLD median delay: {math.exp(old_timing[0]):.1f} ms")
    print(f"  NEW median delay: {math.exp(new_timing[0]):.1f} ms")

    print("\nBurst config:")
    old_burst = current["burst_config"]
    new_burst = new_profile["burst_config"]
    for key in ["min_burst_bytes", "max_burst_bytes", "min_pause_ms", "max_pause_ms"]:
        print(f"  {key}: OLD={old_burst[key]}, NEW={new_burst[key]}")
    old_bc = old_burst["burst_count_distribution"]["params"]
    new_bc = new_burst["burst_count_distribution"]["params"]
    print(f"  burst_count: OLD=[{old_bc[0]}, {old_bc[1]}], NEW=[{new_bc[0]}, {new_bc[1]}]")

    # Output the new profile JSON for easy copy
    print("\n" + "=" * 70)
    print("NEW PROFILE JSON:")
    print("=" * 70)
    print(new_json)

    return new_profile


if __name__ == "__main__":
    main()
