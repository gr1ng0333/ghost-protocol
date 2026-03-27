// Command stresstest runs black-box stress scenarios against a live Ghost
// deployment through its SOCKS5 proxy. It assumes ghost-client is already
// running with a SOCKS5 listener.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// flags
var (
	flagSocks    string
	flagServer   string
	flagScenario string
	flagDuration string
)

func init() {
	flag.StringVar(&flagSocks, "socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	flag.StringVar(&flagServer, "server", "94.156.122.66:443", "Ghost server address")
	flag.StringVar(&flagScenario, "scenario", "all", "Scenario: all, streams, churn, sustained, reconnect, parallel, health")
	flag.StringVar(&flagDuration, "duration", "10m", "Duration for sustained test")
}

func main() {
	flag.Parse()

	fmt.Println("=== Ghost Stress Test ===")
	fmt.Printf("Date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("Server: %s\n", flagServer)
	fmt.Printf("Proxy: %s\n", flagSocks)
	fmt.Println()

	scenarios := map[string]func(){
		"streams":   scenarioStreams,
		"churn":     scenarioChurn,
		"sustained": scenarioSustained,
		"reconnect": scenarioReconnect,
		"parallel":  scenarioParallel,
		"health":    scenarioHealth,
	}

	order := []string{"streams", "churn", "sustained", "reconnect", "parallel", "health"}

	if flagScenario == "all" {
		for _, name := range order {
			scenarios[name]()
			fmt.Println()
		}
	} else {
		fn, ok := scenarios[flagScenario]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown scenario: %q\n", flagScenario)
			os.Exit(1)
		}
		fn()
	}
}

type memSample struct {
	t         time.Time
	heapAlloc uint64
	sys       uint64
	numGC     uint32
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func socksDialer() (proxy.Dialer, error) {
	return proxy.SOCKS5("tcp", flagSocks, nil, proxy.Direct)
}

func socksHTTPClient(timeout time.Duration) (*http.Client, error) {
	dialer, err := socksDialer()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConnsPerHost: 0, // no keep-alive pooling; each request gets a fresh conn
		DisableKeepAlives:   true,
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func median(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func avg(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	var total time.Duration
	for _, v := range vals {
		total += v
	}
	return total / time.Duration(len(vals))
}

// ---------------------------------------------------------------------------
// Scenario 1: 100 Concurrent Streams
// ---------------------------------------------------------------------------

func scenarioStreams() {
	fmt.Println("--- Scenario 1: 100 Concurrent Streams ---")

	const n = 100
	client, err := socksHTTPClient(60 * time.Second)
	if err != nil {
		fmt.Printf("Status: FAIL\nError: %v\n", err)
		return
	}

	type result struct {
		ok      bool
		latency time.Duration
		err     error
	}
	results := make([]result, n)

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			t0 := time.Now()
			resp, reqErr := client.Get("https://httpbin.org/bytes/102400")
			if reqErr != nil {
				results[idx] = result{err: reqErr}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results[idx] = result{ok: resp.StatusCode == 200, latency: time.Since(t0)}
			if resp.StatusCode != 200 {
				results[idx].err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	wallTime := time.Since(start)

	var successes, failures int
	var latencies []time.Duration
	for _, r := range results {
		if r.ok {
			successes++
			latencies = append(latencies, r.latency)
		} else {
			failures++
			if r.err != nil {
				fmt.Printf("  error: %v\n", r.err)
			}
		}
	}

	pass := failures == 0
	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Success: %d/%d\n", successes, n)
	if len(latencies) > 0 {
		fmt.Printf("Avg latency: %s\n", avg(latencies).Round(time.Millisecond))
		fmt.Printf("Median latency: %s\n", median(latencies).Round(time.Millisecond))
	}
	fmt.Printf("Total time: %s\n", wallTime.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// Scenario 2: Rapid Stream Churn
// ---------------------------------------------------------------------------

func scenarioChurn() {
	fmt.Println("--- Scenario 2: Stream Churn ---")

	const (
		workers    = 10
		iterations = 100 // per worker → 1000 total
	)

	goroutinesBefore := runtime.NumGoroutine()

	client, err := socksHTTPClient(30 * time.Second)
	if err != nil {
		fmt.Printf("Status: FAIL\nError: %v\n", err)
		return
	}

	var completed atomic.Int64
	var errors atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				req, _ := http.NewRequest("HEAD", "https://www.google.com/", nil)
				resp, reqErr := client.Do(req)
				if reqErr != nil {
					errors.Add(1)
					continue
				}
				resp.Body.Close()
				completed.Add(1)
			}
		}()
	}
	wg.Wait()
	wallTime := time.Since(start)

	// Let goroutines settle.
	time.Sleep(5 * time.Second)
	goroutinesAfter := runtime.NumGoroutine()
	delta := goroutinesAfter - goroutinesBefore

	total := completed.Load() + errors.Load()
	rate := float64(total) / wallTime.Seconds()

	pass := errors.Load() == 0 && delta <= 5
	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Completed: %d/%d\n", completed.Load(), workers*iterations)
	fmt.Printf("Errors: %d\n", errors.Load())
	fmt.Printf("Rate: %.1f streams/sec\n", rate)
	fmt.Printf("Goroutines before: %d, after: %d, delta: %d\n", goroutinesBefore, goroutinesAfter, delta)
	fmt.Printf("Total time: %s\n", wallTime.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// Scenario 3: Sustained Throughput
// ---------------------------------------------------------------------------

func scenarioSustained() {
	fmt.Println("--- Scenario 3: Sustained Throughput ---")

	dur, err := time.ParseDuration(flagDuration)
	if err != nil {
		fmt.Printf("Status: FAIL\nError: bad duration: %v\n", err)
		return
	}

	dialer, err := socksDialer()
	if err != nil {
		fmt.Printf("Status: FAIL\nError: %v\n", err)
		return
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport}

	var samples []memSample
	var totalBytes int64

	deadline := time.Now().Add(dur)
	sampleTick := time.NewTicker(30 * time.Second)
	defer sampleTick.Stop()

	// Capture initial memory.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	samples = append(samples, memSample{time.Now(), ms.HeapAlloc, ms.Sys, ms.NumGC})

	start := time.Now()
	buf := make([]byte, 256*1024) // 256KB read buffer

	for time.Now().Before(deadline) {
		resp, reqErr := client.Get("https://speed.hetzner.de/100MB.bin")
		if reqErr != nil {
			fmt.Printf("  download error: %v\n", reqErr)
			time.Sleep(2 * time.Second)
			continue
		}

		for time.Now().Before(deadline) {
			n, readErr := resp.Body.Read(buf)
			totalBytes += int64(n)

			select {
			case <-sampleTick.C:
				runtime.ReadMemStats(&ms)
				samples = append(samples, memSample{time.Now(), ms.HeapAlloc, ms.Sys, ms.NumGC})
				fmt.Printf("  [%s] heap=%dMB sys=%dMB gc=%d transferred=%dMB\n",
					time.Since(start).Round(time.Second),
					ms.HeapAlloc/1024/1024, ms.Sys/1024/1024, ms.NumGC,
					totalBytes/1024/1024)
			default:
			}

			if readErr != nil {
				break
			}
		}
		resp.Body.Close()
	}
	wallTime := time.Since(start)

	// Final memory sample.
	runtime.ReadMemStats(&ms)
	samples = append(samples, memSample{time.Now(), ms.HeapAlloc, ms.Sys, ms.NumGC})

	throughputMbps := float64(totalBytes) * 8 / wallTime.Seconds() / 1e6

	// Check memory stability: avg of first 5 vs last 5 samples.
	pass := true
	var maxHeap uint64
	for _, s := range samples {
		if s.heapAlloc > maxHeap {
			maxHeap = s.heapAlloc
		}
	}
	if len(samples) >= 10 {
		avgFirst := avgHeap(samples[:5])
		avgLast := avgHeap(samples[len(samples)-5:])
		if avgLast > 2*avgFirst {
			pass = false
		}
	}

	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Duration: %s\n", wallTime.Round(time.Second))
	fmt.Printf("Transferred: %d MB\n", totalBytes/1024/1024)
	fmt.Printf("Avg throughput: %.1f Mbps\n", throughputMbps)
	fmt.Printf("Max HeapAlloc: %d MB\n", maxHeap/1024/1024)
	fmt.Printf("Memory samples: %d\n", len(samples))
}

func avgHeap(samples []memSample) uint64 {
	if len(samples) == 0 {
		return 0
	}
	var sum uint64
	for _, s := range samples {
		sum += s.heapAlloc
	}
	return sum / uint64(len(samples))
}

// ---------------------------------------------------------------------------
// Scenario 4: Reconnection Storm
// ---------------------------------------------------------------------------

func scenarioReconnect() {
	fmt.Println("--- Scenario 4: Reconnection Storm ---")

	const cycles = 10
	var successes, failures int
	var latencies []time.Duration

	for i := 0; i < cycles; i++ {
		client, err := socksHTTPClient(30 * time.Second)
		if err != nil {
			fmt.Printf("  cycle %d: dialer error: %v\n", i+1, err)
			failures++
			continue
		}

		t0 := time.Now()
		resp, err := client.Get("https://www.google.com/")
		lat := time.Since(t0)
		if err != nil {
			fmt.Printf("  cycle %d: request error: %v\n", i+1, err)
			failures++
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		fmt.Printf("  cycle %d: HTTP %d, latency %s\n", i+1, resp.StatusCode, lat.Round(time.Millisecond))
		successes++
		latencies = append(latencies, lat)

		if i < cycles-1 {
			time.Sleep(30 * time.Second)
		}
	}

	pass := failures == 0
	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Success: %d/%d\n", successes, cycles)
	if len(latencies) > 0 {
		fmt.Printf("Avg latency: %s\n", avg(latencies).Round(time.Millisecond))
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: Parallel Downloads
// ---------------------------------------------------------------------------

func scenarioParallel() {
	fmt.Println("--- Scenario 5: Parallel Downloads ---")

	const n = 5
	const url = "https://speed.hetzner.de/10MB.bin"

	type result struct {
		bytes   int64
		latency time.Duration
		err     error
	}
	results := make([]result, n)

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client, err := socksHTTPClient(120 * time.Second)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			t0 := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results[idx] = result{bytes: n, latency: time.Since(t0)}
		}(i)
	}
	wg.Wait()
	wallTime := time.Since(start)

	var totalBytes int64
	var completions int
	for i, r := range results {
		if r.err != nil {
			fmt.Printf("  download %d: error: %v\n", i+1, r.err)
		} else {
			mbps := float64(r.bytes) * 8 / r.latency.Seconds() / 1e6
			fmt.Printf("  download %d: %d MB in %s (%.1f Mbps)\n",
				i+1, r.bytes/1024/1024, r.latency.Round(time.Millisecond), mbps)
			totalBytes += r.bytes
			completions++
		}
	}

	combinedMbps := float64(totalBytes) * 8 / wallTime.Seconds() / 1e6
	pass := completions == n
	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Completed: %d/%d\n", completions, n)
	fmt.Printf("Combined throughput: %.1f Mbps\n", combinedMbps)
	fmt.Printf("Total time: %s\n", wallTime.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// Scenario 6: Health Under Load
// ---------------------------------------------------------------------------

func scenarioHealth() {
	fmt.Println("--- Scenario 6: Health Under Load ---")

	// Baseline: single health check before any load.
	client, err := socksHTTPClient(30 * time.Second)
	if err != nil {
		fmt.Printf("Status: FAIL\nError: %v\n", err)
		return
	}

	baselineStart := time.Now()
	resp, err := client.Head("https://www.google.com/")
	baselineLatency := time.Since(baselineStart)
	if err != nil {
		fmt.Printf("Status: FAIL\nBaseline error: %v\n", err)
		return
	}
	resp.Body.Close()
	fmt.Printf("  Baseline health check: %s\n", baselineLatency.Round(time.Millisecond))

	// URLs for load generation.
	loadURLs := []string{
		"https://www.google.com/",
		"https://www.cloudflare.com/",
		"https://example.com/",
		"https://www.wikipedia.org/",
		"https://www.github.com/",
		"https://httpbin.org/bytes/51200",
		"https://www.apple.com/",
		"https://www.microsoft.com/",
		"https://www.amazon.com/",
		"https://www.facebook.com/",
		"https://www.twitter.com/",
		"https://www.reddit.com/",
		"https://www.stackoverflow.com/",
		"https://www.netflix.com/",
		"https://www.linkedin.com/",
		"https://www.yahoo.com/",
		"https://www.bing.com/",
		"https://www.duckduckgo.com/",
		"https://www.mozilla.org/",
		"https://www.debian.org/",
	}

	var loadWG sync.WaitGroup
	loadStarted := make(chan struct{})

	// Start 20 concurrent load requests.
	for i := 0; i < 20; i++ {
		loadWG.Add(1)
		go func(idx int) {
			defer loadWG.Done()
			<-loadStarted
			c, cErr := socksHTTPClient(60 * time.Second)
			if cErr != nil {
				return
			}
			resp, reqErr := c.Get(loadURLs[idx%len(loadURLs)])
			if reqErr != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}

	// Health check goroutine: 10 sequential checks during load.
	var healthLatencies []time.Duration
	var healthErrors int
	healthDone := make(chan struct{})

	go func() {
		defer close(healthDone)
		<-loadStarted
		// Small delay so load goroutines are in flight.
		time.Sleep(500 * time.Millisecond)
		for i := 0; i < 10; i++ {
			hc, hErr := socksHTTPClient(30 * time.Second)
			if hErr != nil {
				healthErrors++
				continue
			}
			t0 := time.Now()
			r, rErr := hc.Head("https://www.google.com/")
			lat := time.Since(t0)
			if rErr != nil {
				healthErrors++
				continue
			}
			r.Body.Close()
			healthLatencies = append(healthLatencies, lat)
		}
	}()

	close(loadStarted) // fire!
	loadWG.Wait()
	<-healthDone

	// Evaluate.
	pass := true
	if healthErrors > 0 {
		pass = false
	}
	var avgHealth time.Duration
	if len(healthLatencies) > 0 {
		avgHealth = avg(healthLatencies)
		threshold := time.Duration(float64(baselineLatency) * 5)
		if threshold < 5*time.Second {
			threshold = 5 * time.Second // floor to avoid noisy baselines
		}
		if avgHealth > threshold {
			pass = false
		}
	} else {
		pass = false
	}

	status := "PASS"
	if !pass {
		status = "FAIL"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Baseline latency: %s\n", baselineLatency.Round(time.Millisecond))
	fmt.Printf("Health checks: %d ok, %d errors\n", len(healthLatencies), healthErrors)
	if len(healthLatencies) > 0 {
		fmt.Printf("Avg health latency under load: %s\n", avgHealth.Round(time.Millisecond))
		ratio := float64(avgHealth) / math.Max(float64(baselineLatency), 1)
		fmt.Printf("Ratio vs baseline: %.1fx\n", ratio)
	}
}
