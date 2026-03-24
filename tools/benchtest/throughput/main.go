package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
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

// result captures one throughput measurement.
type result struct {
	Mode     string
	Bytes    int64
	Duration time.Duration
	Mbps     float64
	Target   float64
	Pass     bool
}

func main() {
	modeFlag := flag.String("mode", "all", "Shaping mode: performance|balanced|stealth|all")
	duration := flag.Duration("duration", 10*time.Second, "Test duration per mode")
	chunk := flag.Int("chunk", 65536, "Write chunk size in bytes")
	flag.Parse()

	modes := map[string]struct {
		mode   shaping.Mode
		target float64
	}{
		"performance": {shaping.ModePerformance, 150},
		"balanced":    {shaping.ModeBalanced, 100},
		"stealth":     {shaping.ModeStealth, 30},
	}

	var order []string
	if *modeFlag == "all" {
		order = []string{"performance", "balanced", "stealth"}
	} else {
		if _, ok := modes[*modeFlag]; !ok {
			fmt.Fprintf(os.Stderr, "unknown mode %q; use performance|balanced|stealth|all\n", *modeFlag)
			os.Exit(1)
		}
		order = []string{*modeFlag}
	}

	var results []result
	for _, name := range order {
		m := modes[name]
		fmt.Printf("Testing %s mode (duration=%v, chunk=%d)...\n", name, *duration, *chunk)
		r, err := runThroughput(m.mode, *duration, *chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			results = append(results, result{Mode: name, Target: m.target})
			continue
		}
		r.Mode = name
		r.Target = m.target
		r.Pass = r.Mbps >= m.target
		results = append(results, r)
		fmt.Printf("  %.1f Mbps\n", r.Mbps)
	}

	// Summary table
	fmt.Println()
	fmt.Printf("%-14s| %-18s| %-8s| %s\n", "Mode", "Throughput (Mbps)", "Target", "Pass")
	fmt.Printf("--------------+-------------------+---------+------\n")
	for _, r := range results {
		pass := "❌"
		if r.Pass {
			pass = "✅"
		}
		tp := "ERR"
		if r.Mbps > 0 {
			tp = fmt.Sprintf("%.1f", r.Mbps)
		}
		fmt.Printf("%-14s| %-18s| ≥%-6.0f | %s\n", r.Mode, tp, r.Target, pass)
	}
}

// setupMuxPair creates a connected ClientMux + ServerMux with optional shaping.
// For performance mode: no shaping wrappers (passthrough).
// For balanced/stealth: PadderFrameWriter + TimerFrameWriter on write path,
// UnpadderFrameReader on read path.
func setupMuxPair(mode shaping.Mode) (mux.ClientMux, mux.ServerMux, func()) {
	// Client writes → Server reads (upstream)
	upR, upW := io.Pipe()
	// Server writes → Client reads (downstream)
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

		var profile *shaping.Profile
		switch mode {
		case shaping.ModeBalanced:
			// Balanced: light timing - small per-frame delays, large bursts, short pauses.
			profile = &shaping.Profile{
				Name: "balanced-bench",
				SizeDist: shaping.Distribution{
					Type:   "uniform",
					Params: []float64{512, 1400},
				},
				TimingDist: shaping.Distribution{
					Type:   "uniform",
					Params: []float64{0, 0.01}, // 0-10μs per frame
				},
				BurstConf: shaping.BurstConfig{
					MinBurstBytes: 1 << 20, // 1MB bursts
					MaxBurstBytes: 4 << 20, // 4MB bursts
					MinPauseMs:    1,
					MaxPauseMs:    3,
				},
			}
		default: // ModeStealth
			// Stealth: heavier timing - noticeable per-frame delays, smaller bursts.
			profile = &shaping.Profile{
				Name: "stealth-bench",
				SizeDist: shaping.Distribution{
					Type:   "uniform",
					Params: []float64{256, 1024},
				},
				TimingDist: shaping.Distribution{
					Type:   "uniform",
					Params: []float64{0.01, 0.1}, // 10-100μs per frame
				},
				BurstConf: shaping.BurstConfig{
					MinBurstBytes: 256 << 10, // 256KB bursts
					MaxBurstBytes: 512 << 10, // 512KB bursts
					MinPauseMs:    5,
					MaxPauseMs:    15,
				},
			}
		}

		timer := shaping.NewProfileTimer(profile, 42)

		// Client write path: mux → timer → padder → encoder
		clientPadWriter := &shaping.PadderFrameWriter{Padder: padder, Next: clientEncBase}
		clientWriter = &shaping.TimerFrameWriter{Timer: timer, Selector: sel, Next: clientPadWriter}
		// Client read path: decoder → unpadder → mux
		clientReader = &shaping.UnpadderFrameReader{Padder: padder, Src: clientDecBase}

		// Server write path: mux → timer → padder → encoder
		serverPadWriter := &shaping.PadderFrameWriter{Padder: padder, Next: serverEncBase}
		serverWriter = &shaping.TimerFrameWriter{Timer: timer, Selector: sel, Next: serverPadWriter}
		// Server read path: decoder → unpadder → mux
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

	return client, server, cleanup
}

func runThroughput(mode shaping.Mode, duration time.Duration, chunkSize int) (result, error) {
	client, server, cleanup := setupMuxPair(mode)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), duration+30*time.Second)
	defer cancel()

	var totalBytes atomic.Int64
	var wg sync.WaitGroup

	// Server side: accept stream and read/discard all data.
	wg.Add(1)
	go func() {
		defer wg.Done()
		stream, _, err := server.Accept(ctx)
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, chunkSize)
		for {
			n, err := stream.Read(buf)
			totalBytes.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()

	// Client side: open stream and write data continuously.
	stream, err := client.Open(ctx, "bench.local", 9999)
	if err != nil {
		return result{}, fmt.Errorf("client.Open: %w", err)
	}

	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	start := time.Now()
	deadline := start.Add(duration)
	for time.Now().Before(deadline) {
		_, err := stream.Write(data)
		if err != nil {
			break
		}
	}
	stream.Close()
	elapsed := time.Since(start)

	// Give server goroutine time to finish reading.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

	bytes := totalBytes.Load()
	mbps := float64(bytes) * 8 / elapsed.Seconds() / 1e6

	return result{
		Bytes:    bytes,
		Duration: elapsed,
		Mbps:     mbps,
	}, nil
}
