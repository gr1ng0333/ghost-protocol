//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "SOCKS5 dialer error: %v\n", err)
		os.Exit(1)
	}
	client := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   15 * time.Second,
	}

	urls := []string{
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://httpbin.org/ip",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
	}

	for i, u := range urls {
		start := time.Now()
		resp, err := client.Get(u)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("Req %d: ERROR %v (%s)\n", i+1, err, elapsed)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Req %d: HTTP %d (%s)\n", i+1, resp.StatusCode, elapsed.Round(time.Millisecond))
		time.Sleep(1 * time.Second)
	}

	// Quick throughput test — 10MB download via Cloudflare
	fmt.Println("\nThroughput test (10MB)...")
	dlClient := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   60 * time.Second,
	}
	start := time.Now()
	resp, err := dlClient.Get("https://speed.cloudflare.com/__down?bytes=10485760")
	if err != nil {
		fmt.Printf("Throughput: ERROR %v\n", err)
	} else {
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		mbps := float64(n) / elapsed.Seconds() / 1024 / 1024
		fmt.Printf("Throughput: %d bytes in %s (%.2f MB/s)\n", n, elapsed.Round(time.Millisecond), mbps)
	}

	fmt.Println("\nAll requests complete.")
}
