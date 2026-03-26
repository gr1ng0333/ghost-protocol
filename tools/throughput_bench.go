//go:build ignore
// +build ignore

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	modes := []struct {
		name   string
		config string
	}{
		{"performance", "configs/client-perf.yaml"},
		{"balanced", "configs/client-balanced.yaml"},
		{"stealth", "configs/client-stealth.yaml"},
	}

	// Check if a specific mode was requested
	requestedMode := ""
	if len(os.Args) > 1 {
		requestedMode = os.Args[1]
	}

	fmt.Println("=== Ghost VPN Throughput & Latency Test ===")
	fmt.Printf("Time: %s\n\n", time.Now().Format(time.RFC3339))

	// Direct baseline first
	if requestedMode == "" || requestedMode == "direct" {
		fmt.Println("========================================")
		fmt.Println("  DIRECT BASELINE (no proxy)")
		fmt.Println("========================================")
		directClient := &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		}
		runThroughputTests(directClient, "direct", 100*1024*1024, 3)
		runLatencyTests(directClient, "direct", 5)
		fmt.Println()
	}

	// Test each mode via SOCKS5
	for _, mode := range modes {
		if requestedMode != "" && requestedMode != mode.name && requestedMode != "all" {
			continue
		}

		fmt.Println("========================================")
		fmt.Printf("  MODE: %s\n", mode.name)
		fmt.Printf("  Config: %s\n", mode.config)
		fmt.Println("========================================")
		fmt.Println("  (Assumes ghost-client is running with this config)")
		fmt.Println()

		client, err := makeSocksClient("127.0.0.1:1080")
		if err != nil {
			fmt.Printf("  ERROR: Cannot create SOCKS5 client: %v\n", err)
			continue
		}

		// Verify connectivity
		fmt.Print("  Connectivity check... ")
		if err := checkConnectivity(client); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fmt.Println("  Skipping this mode (client not running?)")
			fmt.Println()
			continue
		}
		fmt.Println("OK")

		dlSize := 100 * 1024 * 1024 // 100MB
		if mode.name == "stealth" {
			dlSize = 50 * 1024 * 1024 // 50MB for stealth
		}

		runThroughputTests(client, mode.name, dlSize, 3)
		runLatencyTests(client, mode.name, 5)
		fmt.Println()
	}

	fmt.Println("=== Test Complete ===")
}

func makeSocksClient(proxyAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}

	return &http.Client{
		Timeout:   180 * time.Second,
		Transport: transport,
	}, nil
}

func checkConnectivity(client *http.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.google.com/", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func runThroughputTests(client *http.Client, mode string, size int, runs int) {
	sizeMB := float64(size) / (1024 * 1024)
	fmt.Printf("\n  --- Download Tests (%.0f MB, %d runs) ---\n", sizeMB, runs)

	urls := []string{
		fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", size),
		"https://proof.ovh.net/files/100Mb.dat",
		"https://ash-speed.hetzner.com/100MB.bin",
	}
	var speeds []float64

	// Find a working URL first
	workingURL := ""
	for _, u := range urls {
		fmt.Printf("  Trying URL: %s ... ", u)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		fmt.Printf("HTTP %d, Content-Length: %d\n", resp.StatusCode, resp.ContentLength)
		// Read a bit to see if data flows
		buf := make([]byte, 4096)
		n, _ := io.ReadAtLeast(resp.Body, buf, 1)
		resp.Body.Close()
		cancel()
		if n > 0 && resp.StatusCode == 200 {
			workingURL = u
			fmt.Printf("  Selected: %s (%d bytes test read)\n", u, n)
			break
		}
	}

	if workingURL == "" {
		fmt.Println("  ERROR: No working download URL found!")
		return
	}

	for i := 1; i <= runs; i++ {
		fmt.Printf("  Run %d: ", i)

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)

		req, err := http.NewRequestWithContext(ctx, "GET", workingURL, nil)
		if err != nil {
			cancel()
			fmt.Printf("ERROR creating request: %v\n", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			fmt.Printf("ERROR: %v\n", err)
			continue
		}

		n, err := io.Copy(io.Discard, resp.Body)
		elapsed := time.Since(start)
		resp.Body.Close()
		cancel()

		if err != nil {
			fmt.Printf("ERROR reading: %v (got %d bytes in %v)\n", err, n, elapsed)
			if n > 0 {
				mbps := float64(n) * 8 / elapsed.Seconds() / 1e6
				speeds = append(speeds, mbps)
				fmt.Printf("         Partial: %.2f Mbps (%.2f MB in %.1fs)\n",
					mbps, float64(n)/(1024*1024), elapsed.Seconds())
			}
			continue
		}

		mbps := float64(n) * 8 / elapsed.Seconds() / 1e6
		speeds = append(speeds, mbps)
		fmt.Printf("%.2f Mbps (%.2f MB in %.1fs)\n",
			mbps, float64(n)/(1024*1024), elapsed.Seconds())

		if i < runs {
			time.Sleep(2 * time.Second)
		}
	}

	if len(speeds) > 0 {
		sort.Float64s(speeds)
		avg := 0.0
		for _, s := range speeds {
			avg += s
		}
		avg /= float64(len(speeds))
		med := speeds[len(speeds)/2]

		fmt.Printf("  Summary [%s]: avg=%.2f Mbps, median=%.2f Mbps, min=%.2f, max=%.2f\n",
			mode, avg, med, speeds[0], speeds[len(speeds)-1])
	}
}

func runLatencyTests(client *http.Client, mode string, count int) {
	fmt.Printf("\n  --- Latency Tests (%d measurements) ---\n", count)

	var ttfbs []float64
	var totals []float64

	for i := 1; i <= count; i++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		req, err := http.NewRequestWithContext(ctx, "GET", "https://www.google.com/", nil)
		if err != nil {
			cancel()
			fmt.Printf("  [%d] ERROR: %v\n", i, err)
			continue
		}

		resp, err := client.Do(req)
		ttfb := time.Since(start)
		if err != nil {
			cancel()
			fmt.Printf("  [%d] ERROR: %v\n", i, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		total := time.Since(start)
		cancel()

		ttfbMs := float64(ttfb.Microseconds()) / 1000
		totalMs := float64(total.Microseconds()) / 1000
		ttfbs = append(ttfbs, ttfbMs)
		totals = append(totals, totalMs)

		fmt.Printf("  [%d] TTFB: %.1fms  Total: %.1fms\n", i, ttfbMs, totalMs)

		if i < count {
			time.Sleep(1 * time.Second)
		}
	}

	if len(ttfbs) > 0 {
		sort.Float64s(ttfbs)
		sort.Float64s(totals)
		medTTFB := ttfbs[len(ttfbs)/2]
		medTotal := totals[len(totals)/2]
		p95TTFB := percentile(ttfbs, 95)
		p95Total := percentile(totals, 95)

		fmt.Printf("  Summary [%s]: TTFB median=%.1fms p95=%.1fms | Total median=%.1fms p95=%.1fms\n",
			mode, medTTFB, p95TTFB, medTotal, p95Total)
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := p / 100.0 * float64(len(sorted)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper || upper >= len(sorted) {
		return sorted[lower]
	}
	frac := rank - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}
