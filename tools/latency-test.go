//go:build ignore

package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{Timeout: 15 * time.Second}
	urls := []string{"https://www.google.com/", "https://www.cloudflare.com/", "https://www.github.com/"}

	for _, url := range urls {
		fmt.Printf("\n--- %s ---\n", url)
		for i := 0; i < 5; i++ {
			start := time.Now()
			resp, err := client.Get(url)
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
}
