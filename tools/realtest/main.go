//go:build ignore

// Real-world throughput measurement tool for Ghost VPN.
// Connects through the Ghost SOCKS5 proxy and measures download/upload speeds.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	testURL := flag.String("url", "https://speed.cloudflare.com/__down?bytes=10485760", "Download test URL")
	runs := flag.Int("runs", 3, "Number of runs")
	mode := flag.String("mode", "download", "Test mode: download|latency")
	flag.Parse()

	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SOCKS5 dial error: %v\n", err)
		os.Exit(1)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: false,
	}
	client := &http.Client{Transport: transport, Timeout: 120 * time.Second}

	switch *mode {
	case "download":
		runDownload(client, *testURL, *runs)
	case "latency":
		runLatency(client, *runs)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(1)
	}
	_ = rand.Reader // suppress unused import
}

func runDownload(client *http.Client, url string, runs int) {
	var totalMbps float64
	for i := 0; i < runs; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("  Run %d: ERROR %v\n", i+1, err)
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		mbps := float64(n*8) / elapsed.Seconds() / 1e6
		totalMbps += mbps
		fmt.Printf("  Run %d: %.2f MB in %.2fs = %.2f Mbps\n", i+1, float64(n)/1e6, elapsed.Seconds(), mbps)
	}
	fmt.Printf("  Average: %.2f Mbps\n", totalMbps/float64(runs))
}

func runLatency(client *http.Client, runs int) {
	for i := 0; i < runs; i++ {
		start := time.Now()
		resp, err := client.Get("https://www.google.com/")
		if err != nil {
			fmt.Printf("  Run %d: ERROR %v\n", i+1, err)
			continue
		}
		ttfb := time.Since(start)
		io.Copy(io.Discard, resp.Body)
		total := time.Since(start)
		resp.Body.Close()
		fmt.Printf("  Run %d: TTFB=%dms Total=%dms HTTP=%d\n", i+1, ttfb.Milliseconds(), total.Milliseconds(), resp.StatusCode)
	}
}
