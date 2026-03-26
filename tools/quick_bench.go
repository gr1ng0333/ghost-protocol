//go:build ignore
// +build ignore

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	mode := "performance"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	sizeMB := 10
	if len(os.Args) > 2 && os.Args[2] == "small" {
		sizeMB = 5
	}
	sizeBytes := int64(sizeMB) * 1024 * 1024

	fmt.Printf("[%s] Testing %d MB download via socks5://127.0.0.1:1080\n", mode, sizeMB)

	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
	if err != nil {
		fmt.Printf("SOCKS5 error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	// Use Hetzner speed test as backup
	urls := []string{
		fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", sizeBytes),
		"https://proof.ovh.net/files/10Mb.dat",
		"https://ash-speed.hetzner.com/100MB.bin",
	}

	for _, url := range urls {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			cancel()
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		elapsed := time.Since(start)
		resp.Body.Close()
		cancel()

		if n > 0 {
			mbps := float64(n) * 8 / elapsed.Seconds() / 1e6
			fmt.Printf("[%s] Downloaded %.2f MB in %.1fs = %.2f Mbps\n",
				mode, float64(n)/(1024*1024), elapsed.Seconds(), mbps)
			return
		}
	}
	fmt.Printf("[%s] ERROR: No working download URL\n", mode)
}
