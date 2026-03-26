package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	socksAddr := "127.0.0.1:1080"
	if len(os.Args) > 1 {
		socksAddr = os.Args[1]
	}

	targetURL := "https://tls.peet.ws/api/all"
	if len(os.Args) > 2 {
		targetURL = os.Args[2]
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
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET %s failed: %v\n", targetURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read body: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print if JSON
	var js json.RawMessage
	if json.Unmarshal(body, &js) == nil {
		pretty, err := json.MarshalIndent(js, "", "  ")
		if err == nil {
			fmt.Println(string(pretty))
			return
		}
	}
	fmt.Println(string(body))
}
