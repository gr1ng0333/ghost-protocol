package shaping

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"ghost/internal/framing"
)

// Cover traffic pattern weights.
const (
	weightKeepAlive = 60
	weightAnalytics = 30
	weightMiniBurst = 10
	weightTotal     = weightKeepAlive + weightAnalytics + weightMiniBurst
)

// pattern identifies which cover traffic pattern to inject.
type pattern int

const (
	patternKeepAlive pattern = iota
	patternAnalytics
	patternMiniBurst
)

// CoverGenerator produces background traffic during idle periods.
// It injects FramePadding and FrameKeepAlive frames into the pipeline
// to simulate Chrome idle behavior patterns.
type CoverGenerator struct {
	writer   framing.FrameWriter
	selector Selector
	profile  *Profile
	rng      *rand.Rand

	mu          sync.Mutex
	streamCount int
	byteRate    int64
	running     bool
	stopCh      chan struct{}
	lastPattern pattern
}

// NewCoverGenerator creates a CoverGenerator.
// writer is the FrameWriter the mux also uses (cover traffic goes through padder+timer).
// selector checks current mode. profile provides timing parameters.
// seed is for the RNG (use time.Now().UnixNano() in production, fixed seed in tests).
func NewCoverGenerator(writer framing.FrameWriter, selector Selector, profile *Profile, seed int64) *CoverGenerator {
	return &CoverGenerator{
		writer:   writer,
		selector: selector,
		profile:  profile,
		rng:      rand.New(rand.NewSource(seed)),
	}
}

// Start begins the cover traffic goroutine. Runs until Stop() or ctx cancellation.
func (cg *CoverGenerator) Start(ctx context.Context) {
	cg.mu.Lock()
	if cg.running {
		cg.mu.Unlock()
		return
	}
	cg.running = true
	cg.stopCh = make(chan struct{})
	cg.mu.Unlock()

	go cg.run(ctx)
}

// Stop halts the cover traffic goroutine. Safe to call multiple times.
func (cg *CoverGenerator) Stop() {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	if !cg.running {
		return
	}
	cg.running = false
	close(cg.stopCh)
}

// UpdateStats informs the generator of current traffic state.
// Called periodically by StatsUpdater.
func (cg *CoverGenerator) UpdateStats(byteRate int64, streamCount int) {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	cg.byteRate = byteRate
	cg.streamCount = streamCount
}

func (cg *CoverGenerator) run(ctx context.Context) {
	// Short initial interval (5–15s) so idle detection kicks in promptly.
	cg.mu.Lock()
	initialDelay := time.Duration(5000+cg.rng.Intn(10001)) * time.Millisecond
	cg.mu.Unlock()

	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cg.stopCh:
			return
		case <-timer.C:
			cg.mu.Lock()
			sc := cg.streamCount
			br := cg.byteRate
			cg.mu.Unlock()

			mode := cg.selector.Select(br, sc)
			if mode != ModePerformance && (mode == ModeStealth || sc == 0) {
				cg.injectIdleTraffic()
			}

			cg.mu.Lock()
			next := cg.nextInterval()
			cg.mu.Unlock()
			timer.Reset(next)
		}
	}
}

// nextInterval returns the delay until the next injection based on the
// last selected pattern. Must be called with cg.mu held.
func (cg *CoverGenerator) nextInterval() time.Duration {
	switch cg.lastPattern {
	case patternKeepAlive:
		// 30–60 seconds
		return time.Duration(30000+cg.rng.Intn(30001)) * time.Millisecond
	case patternAnalytics:
		// 60–180 seconds
		return time.Duration(60000+cg.rng.Intn(120001)) * time.Millisecond
	case patternMiniBurst:
		// 180–600 seconds
		return time.Duration(180000+cg.rng.Intn(420001)) * time.Millisecond
	default:
		// Initial: 5–15 seconds
		return time.Duration(5000+cg.rng.Intn(10001)) * time.Millisecond
	}
}

// selectPattern picks a cover traffic pattern using weighted random selection.
// Must be called with cg.mu held.
func (cg *CoverGenerator) selectPattern() pattern {
	roll := cg.rng.Intn(weightTotal)
	switch {
	case roll < weightKeepAlive:
		return patternKeepAlive
	case roll < weightKeepAlive+weightAnalytics:
		return patternAnalytics
	default:
		return patternMiniBurst
	}
}

// injectIdleTraffic selects a random cover traffic pattern and injects
// the appropriate frame(s) through the writer.
func (cg *CoverGenerator) injectIdleTraffic() {
	cg.mu.Lock()
	p := cg.selectPattern()
	cg.lastPattern = p
	cg.mu.Unlock()

	switch p {
	case patternKeepAlive:
		cg.injectKeepAlive()
	case patternAnalytics:
		cg.injectAnalyticsPing()
	case patternMiniBurst:
		cg.injectMiniBurst()
	}
}

func (cg *CoverGenerator) injectKeepAlive() {
	f := &framing.Frame{
		Type:     framing.FrameKeepAlive,
		StreamID: 0,
		Payload:  nil,
	}
	if err := cg.writer.WriteFrame(f); err != nil {
		// Cover traffic errors are non-fatal; connection-level errors
		// will be detected by the mux path.
		_ = fmt.Errorf("cover: keepalive: %w", err)
	}
}

func (cg *CoverGenerator) injectAnalyticsPing() {
	cg.mu.Lock()
	size := 100 + cg.rng.Intn(401) // [100, 500]
	cg.mu.Unlock()

	payload := make([]byte, size)
	cg.mu.Lock()
	cg.rng.Read(payload)
	cg.mu.Unlock()

	f := &framing.Frame{
		Type:     framing.FramePadding,
		StreamID: 0,
		Payload:  payload,
	}
	if err := cg.writer.WriteFrame(f); err != nil {
		_ = fmt.Errorf("cover: analytics: %w", err)
	}
}

func (cg *CoverGenerator) injectMiniBurst() {
	cg.mu.Lock()
	count := 2 + cg.rng.Intn(4) // [2, 5]
	cg.mu.Unlock()

	for i := 0; i < count; i++ {
		cg.mu.Lock()
		size := 50 + cg.rng.Intn(151) // [50, 200]
		cg.mu.Unlock()

		payload := make([]byte, size)
		cg.mu.Lock()
		cg.rng.Read(payload)
		cg.mu.Unlock()

		f := &framing.Frame{
			Type:     framing.FramePadding,
			StreamID: 0,
			Payload:  payload,
		}
		if err := cg.writer.WriteFrame(f); err != nil {
			_ = fmt.Errorf("cover: burst: %w", err)
			return
		}

		// Short delay between burst frames (<500ms).
		if i < count-1 {
			cg.mu.Lock()
			delay := time.Duration(cg.rng.Intn(100)) * time.Millisecond
			cg.mu.Unlock()
			time.Sleep(delay)
		}
	}
}
