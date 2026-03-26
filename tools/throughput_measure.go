//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "SOCKS5 dialer error: %v\n", err)
		os.Exit(1)
	}

	transport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	latencyClient := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	// Connectivity check
	fmt.Println("=== Connectivity Check ===")
	resp, err := client.Get("https://www.google.com/")
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Printf("OK: HTTP %d\n\n", resp.StatusCode)

	// Download throughput (3 runs, 10MB via Cloudflare)
	fmt.Println("=== Download Throughput (3 runs) ===")
	dlURL := "https://speed.cloudflare.com/__down?bytes=10485760"
	var speeds []float64
	for run := 1; run <= 3; run++ {
		fmt.Printf("Run %d: downloading 10MB... ", run)
		start := time.Now()
		resp, err := client.Get(dlURL)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		mbps := float64(n) * 8 / elapsed.Seconds() / 1_000_000
		speed := float64(n) / elapsed.Seconds() / 1024 / 1024
		speeds = append(speeds, mbps)
		fmt.Printf("%d bytes in %s (%.2f MB/s = %.2f Mbps)\n", n, elapsed.Round(time.Millisecond), speed, mbps)
		time.Sleep(2 * time.Second)
	}
	if len(speeds) > 0 {
		sort.Float64s(speeds)
		avg := 0.0
		for _, s := range speeds {
			avg += s
		}
		avg /= float64(len(speeds))
		fmt.Printf("Average: %.2f Mbps, Median: %.2f Mbps, Best: %.2f Mbps\n\n", avg, speeds[len(speeds)/2], speeds[len(speeds)-1])
	}

	// Latency (5 runs)
	fmt.Println("=== Latency (5 runs) ===")
	var latencies []time.Duration
	for i := 1; i <= 5; i++ {
		start := time.Now()
		resp, err := latencyClient.Get("https://www.google.com/")
		if err != nil {
			fmt.Printf("Req %d: ERROR %v\n", i, err)
			continue
		}
		ttfb := time.Since(start)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		total := time.Since(start)
		latencies = append(latencies, ttfb)
		fmt.Printf("Req %d: TTFB %s Total %s HTTP %d\n", i, ttfb.Round(time.Millisecond), total.Round(time.Millisecond), resp.StatusCode)
		time.Sleep(1 * time.Second)
	}
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		fmt.Printf("Median TTFB: %s\n\n", latencies[len(latencies)/2].Round(time.Millisecond))
	}

	// Direct baseline (no proxy)
	fmt.Println("=== Direct Baseline ===")
	directClient := &http.Client{Timeout: 60 * time.Second}
	start := time.Now()
	resp, err = directClient.Get(dlURL)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		mbps := float64(n) * 8 / elapsed.Seconds() / 1_000_000
		fmt.Printf("Direct: %d bytes in %s (%.2f Mbps)\n", n, elapsed.Round(time.Millisecond), mbps)
	}
}
