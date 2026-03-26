//go:build ignore

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	proxyAddr := "127.0.0.1:1080"
	url := "https://proof.ovh.net/files/100Mb.dat"
	runs := 3

	if len(os.Args) > 1 {
		proxyAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		url = os.Args[2]
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SOCKS5 dial: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}

	for i := 1; i <= runs; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("Run %d: ERROR %v\n", i, err)
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		mbps := float64(n*8) / elapsed.Seconds() / 1e6
		fmt.Printf("Run %d: %.2f MB in %.2fs = %.2f Mbps\n", i, float64(n)/1e6, elapsed.Seconds(), mbps)
	}
}
