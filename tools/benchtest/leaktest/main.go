package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"ghost/internal/framing"
	"ghost/internal/mux"
	"ghost/internal/shaping"
)

// fixedSelector always returns the configured mode.
type fixedSelector struct{ mode shaping.Mode }

func (s *fixedSelector) Select(int64, int) shaping.Mode { return s.mode }

func main() {
	testFlag := flag.String("test", "all", "Which test: churn|reconnect|longrun|all")
	streams := flag.Int("streams", 10000, "Streams for churn test")
	reconnects := flag.Int("reconnects", 100, "Reconnect cycles")
	duration := flag.Duration("duration", 2*time.Minute, "Long-run duration")
	flag.Parse()

	tests := map[string]func(){
		"churn":     func() { testChurn(*streams) },
		"reconnect": func() { testReconnect(*reconnects) },
		"longrun":   func() { testLongRun(*duration) },
	}

	var order []string
	if *testFlag == "all" {
		order = []string{"churn", "reconnect", "longrun"}
	} else {
		if _, ok := tests[*testFlag]; !ok {
			fmt.Fprintf(os.Stderr, "unknown test %q; use churn|reconnect|longrun|all\n", *testFlag)
			os.Exit(1)
		}
		order = []string{*testFlag}
	}

	for _, name := range order {
		tests[name]()
		fmt.Println()
	}
}

// muxPair holds a connected client/server mux and its cleanup function.
type muxPair struct {
	client  mux.ClientMux
	server  mux.ServerMux
	cleanup func()
}

func newMuxPair() muxPair {
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	client := mux.NewClientMux(
		&framing.EncoderWriter{Enc: framing.NewEncoder(upW)},
		&framing.DecoderReader{Dec: framing.NewDecoder(downR)},
	)
	server := mux.NewServerMux(
		&framing.EncoderWriter{Enc: framing.NewEncoder(downW)},
		&framing.DecoderReader{Dec: framing.NewDecoder(upR)},
	)

	cleanup := func() {
		client.Close()
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	}

	return muxPair{client, server, cleanup}
}

func newShapedMuxPair(mode shaping.Mode) muxPair {
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	clientEncBase := &framing.EncoderWriter{Enc: framing.NewEncoder(upW)}
	clientDecBase := &framing.DecoderReader{Dec: framing.NewDecoder(downR)}
	serverEncBase := &framing.EncoderWriter{Enc: framing.NewEncoder(downW)}
	serverDecBase := &framing.DecoderReader{Dec: framing.NewDecoder(upR)}

	var clientWriter framing.FrameWriter = clientEncBase
	var clientReader framing.FrameReader = clientDecBase
	var serverWriter framing.FrameWriter = serverEncBase
	var serverReader framing.FrameReader = serverDecBase

	if mode != shaping.ModePerformance {
		padder := &shaping.PassthroughPadder{}
		sel := &fixedSelector{mode: mode}
		timer := &shaping.PassthroughTimer{}

		clientWriter = &shaping.TimerFrameWriter{Timer: timer, Selector: sel, Next: &shaping.PadderFrameWriter{Padder: padder, Next: clientEncBase}}
		clientReader = &shaping.UnpadderFrameReader{Padder: padder, Src: clientDecBase}
		serverWriter = &shaping.TimerFrameWriter{Timer: timer, Selector: sel, Next: &shaping.PadderFrameWriter{Padder: padder, Next: serverEncBase}}
		serverReader = &shaping.UnpadderFrameReader{Padder: padder, Src: serverDecBase}
	}

	client := mux.NewClientMux(clientWriter, clientReader)
	server := mux.NewServerMux(serverWriter, serverReader)

	cleanup := func() {
		client.Close()
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	}

	return muxPair{client, server, cleanup}
}

func forceGC() {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
}

func getMemAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

// testChurn opens and closes many streams, checks for goroutine/memory leaks.
func testChurn(n int) {
	fmt.Printf("=== Stream Churn (%d cycles) ===\n", n)

	forceGC()
	baseGoroutines := runtime.NumGoroutine()
	baseMem := getMemAlloc()

	pair := newMuxPair()
	defer pair.cleanup()

	ctx := context.Background()

	for i := 0; i < n; i++ {
		// Server accepts in a goroutine
		var serverStream mux.Stream
		var acceptErr error
		done := make(chan struct{})
		go func() {
			serverStream, _, acceptErr = pair.server.Accept(ctx)
			close(done)
		}()

		cs, err := pair.client.Open(ctx, "bench.test", 80)
		if err != nil {
			fmt.Printf("  FAIL: client.Open at cycle %d: %v\n", i, err)
			return
		}
		<-done
		if acceptErr != nil {
			fmt.Printf("  FAIL: server.Accept at cycle %d: %v\n", i, acceptErr)
			return
		}

		// Write a small payload
		_, _ = cs.Write([]byte("hello world test payload - 100 bytes of data for the churn test to verify stream lifecycle works properly!"))
		buf := make([]byte, 128)
		_, _ = serverStream.Read(buf)

		cs.Close()
		serverStream.Close()
	}

	pair.cleanup()
	forceGC()

	afterGoroutines := runtime.NumGoroutine()
	afterMem := getMemAlloc()

	goroutineDiff := afterGoroutines - baseGoroutines
	memPct := 0.0
	if baseMem > 0 {
		memPct = float64(afterMem-baseMem) / float64(baseMem) * 100
	}

	goroutinePass := abs(goroutineDiff) <= 5
	memPass := math.Abs(memPct) <= 20

	passStr := func(p bool) string {
		if p {
			return "✅"
		}
		return "❌"
	}

	fmt.Printf("Goroutines: baseline=%d, after=%d, diff=%+d  %s\n",
		baseGoroutines, afterGoroutines, goroutineDiff, passStr(goroutinePass))
	fmt.Printf("Memory: baseline=%.1fMB, after=%.1fMB, diff=%+.1f%%  %s\n",
		float64(baseMem)/1e6, float64(afterMem)/1e6, memPct, passStr(memPass))
}

// testReconnect simulates repeated mux pair creation/destruction.
func testReconnect(n int) {
	fmt.Printf("=== Reconnect Churn (%d cycles) ===\n", n)

	forceGC()
	baseGoroutines := runtime.NumGoroutine()

	ctx := context.Background()

	for i := 0; i < n; i++ {
		pair := newMuxPair()

		// Open 5 streams
		var serverStreams []mux.Stream
		var clientStreams []mux.Stream
		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				s, _, err := pair.server.Accept(ctx)
				if err != nil {
					return
				}
				serverStreams = append(serverStreams, s)
			}
		}()

		for j := 0; j < 5; j++ {
			s, err := pair.client.Open(ctx, "bench.test", uint16(80+j))
			if err != nil {
				fmt.Printf("  FAIL: client.Open at cycle %d stream %d: %v\n", i, j, err)
				pair.cleanup()
				return
			}
			clientStreams = append(clientStreams, s)
		}

		wg.Wait()

		// Close all streams
		for _, s := range clientStreams {
			s.Close()
		}
		for _, s := range serverStreams {
			s.Close()
		}

		pair.cleanup()
	}

	forceGC()
	afterGoroutines := runtime.NumGoroutine()
	goroutineDiff := afterGoroutines - baseGoroutines

	pass := abs(goroutineDiff) <= 10
	passStr := "✅"
	if !pass {
		passStr = "❌"
	}

	fmt.Printf("Goroutines: baseline=%d, after=%d, diff=%+d  %s\n",
		baseGoroutines, afterGoroutines, goroutineDiff, passStr)
}

// testLongRun runs continuous bidirectional traffic and monitors for leaks.
func testLongRun(duration time.Duration) {
	fmt.Printf("=== Long-Running Stability (%v) ===\n", duration)

	pair := newShapedMuxPair(shaping.ModePerformance)
	defer pair.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Server side: accept stream and echo/discard.
	go func() {
		s, _, err := pair.server.Accept(ctx)
		if err != nil {
			return
		}
		defer s.Close()
		buf := make([]byte, 32768)
		for {
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			// Echo back
			_, err = s.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	stream, err := pair.client.Open(ctx, "bench.test", 80)
	if err != nil {
		fmt.Printf("  FAIL: client.Open: %v\n", err)
		return
	}

	// Start writer goroutine
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		data := make([]byte, 4096)
		for !stop.Load() {
			_, err := stream.Write(data)
			if err != nil {
				return
			}
		}
	}()

	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for !stop.Load() {
			_, err := stream.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Sample every 10 seconds
	sampleInterval := 10 * time.Second
	numSamples := int(duration / sampleInterval)
	if numSamples < 2 {
		numSamples = 2
	}

	type sample struct {
		goroutines int
		memAlloc   uint64
		numGC      uint32
	}

	var samples []sample
	for i := 0; i < numSamples; i++ {
		time.Sleep(sampleInterval)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		samples = append(samples, sample{
			goroutines: runtime.NumGoroutine(),
			memAlloc:   m.Alloc,
			numGC:      m.NumGC,
		})
	}

	stop.Store(true)
	stream.Close()
	wg.Wait()

	// Analyze samples
	fmt.Printf("Samples: %d\n", len(samples))

	// Memory trend: linear regression on alloc values
	var sumX, sumY, sumXY, sumX2 float64
	var minG, maxG int
	minG = math.MaxInt32
	for i, s := range samples {
		x := float64(i)
		y := float64(s.memAlloc) / 1e6
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
		if s.goroutines < minG {
			minG = s.goroutines
		}
		if s.goroutines > maxG {
			maxG = s.goroutines
		}
	}
	n := float64(len(samples))
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	// Calculate mean for percentage
	meanMem := sumY / n
	slopePct := 0.0
	if meanMem > 0 {
		slopePct = slope / meanMem * 100
	}

	memPass := math.Abs(slopePct) < 5 // slope less than 5% of mean per sample
	goroutinePass := (maxG - minG) <= 10

	passStr := func(p bool) string {
		if p {
			return "✅"
		}
		return "❌"
	}

	fmt.Printf("Memory trend: %+.1f%% per sample (%s)  %s\n",
		slopePct, trendLabel(slopePct), passStr(memPass))
	fmt.Printf("Goroutine range: [%d, %d] (%s)  %s\n",
		minG, maxG, stabilityLabel(maxG-minG), passStr(goroutinePass))
}

func trendLabel(pct float64) string {
	if math.Abs(pct) < 1 {
		return "stable"
	}
	if pct > 0 {
		return "increasing"
	}
	return "decreasing"
}

func stabilityLabel(diff int) string {
	if diff <= 2 {
		return "stable"
	}
	if diff <= 5 {
		return "minor variation"
	}
	return "variable"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
