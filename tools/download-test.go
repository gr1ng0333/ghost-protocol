//go:build ignore

package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{Timeout: 120 * time.Second}
	urls := []struct{ name, url string }{
		{"Cloudflare 10MB", "https://speed.cloudflare.com/__down?bytes=10485760"},
		{"OVH 10MB", "https://proof.ovh.net/files/10Mb.dat"},
	}
	for _, u := range urls {
		fmt.Printf("\n--- Direct Download: %s ---\n", u.name)
		for i := 0; i < 3; i++ {
			start := time.Now()
			resp, err := client.Get(u.url)
			if err != nil {
				fmt.Printf("  Run %d: ERROR %v\n", i+1, err)
				continue
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			elapsed := time.Since(start)
			mbps := float64(n*8) / elapsed.Seconds() / 1e6
			fmt.Printf("  Run %d: %.2f MB in %.2fs = %.2f Mbps\n", i+1, float64(n)/1e6, elapsed.Seconds(), mbps)
		}
	}
}
