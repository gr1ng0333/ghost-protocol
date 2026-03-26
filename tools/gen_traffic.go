//go:build ignore
// +build ignore

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	useProxy := true
	if len(os.Args) > 1 && os.Args[1] == "direct" {
		useProxy = false
	}

	sites := []string{
		"https://www.google.com/",
		"https://www.github.com/",
		"https://en.wikipedia.org/",
		"https://www.cloudflare.com/",
		"https://www.mozilla.org/",
		"https://httpbin.org/get",
		"https://www.python.org/",
		"https://go.dev/",
		"https://www.reddit.com/",
		"https://news.ycombinator.com/",
	}

	var client *http.Client
	if useProxy {
		dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
			os.Exit(1)
		}
		client = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		}
		fmt.Println("Generating traffic through SOCKS5 proxy...")
	} else {
		client = &http.Client{Timeout: 15 * time.Second}
		fmt.Println("Generating traffic directly...")
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 1; i <= 40; i++ {
		site := sites[rng.Intn(len(sites))]

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", site, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			fmt.Printf("[%2d] %s → ERROR: %v\n", i, site, err)
		} else {
			n, _ := io.Copy(io.Discard, resp.Body)
			elapsed := time.Since(start)
			resp.Body.Close()
			fmt.Printf("[%2d] %s → %d (%d bytes, %.1fs)\n", i, site, resp.StatusCode, n, elapsed.Seconds())
		}
		cancel()

		// Random delay 1-5 seconds
		delay := time.Duration(1000+rng.Intn(4000)) * time.Millisecond
		time.Sleep(delay)
	}

	fmt.Println("Traffic generation complete.")
}
