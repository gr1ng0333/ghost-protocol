package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	socksAddr := "127.0.0.1:1080"

	urls := []string{
		"https://www.cloudflare.com/",
		"https://www.google.com/",
		"https://github.com/",
	}

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks5 dialer: %v\n", err)
		os.Exit(1)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			fmt.Printf("%-40s  ERROR: %v\n", u, err)
			continue
		}
		resp.Body.Close()
		fmt.Printf("%-40s  %d\n", u, resp.StatusCode)
	}
}
