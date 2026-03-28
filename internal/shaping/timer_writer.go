package shaping

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"ghost/internal/framing"
)

var timerFrameCount atomic.Int64

// TimerFrameWriter wraps a Timer, Selector, and downstream FrameWriter.
// It applies inter-frame timing delays based on the current shaping mode.
// In Performance mode, frames pass through with no delay. In Stealth or
// Balanced modes, the Timer determines delays and burst boundaries.
type TimerFrameWriter struct {
	Timer    Timer
	Selector Selector
	Next     framing.FrameWriter

	mu          sync.Mutex
	byteRate    int64
	streamCount int
	burstBytes  int
	burstFrames int
}

// maxStealthDelay caps the per-frame delay in Stealth mode to prevent
// extreme outliers from the heavy-tailed lognormal timing distribution.
const maxStealthDelay = 50 * time.Millisecond

// maxBalancedDelay caps the per-frame delay in Balanced mode.
const maxBalancedDelay = 15 * time.Millisecond

// WriteFrame applies timing shaping and forwards the frame to Next.
//
// Data-carrying frames (Data, Open, Close, UDP) pass through without timing
// delay in ALL modes. The TimerFrameWriter sits on the upload (client→server)
// path; the Chrome browsing timing profile describes download patterns visible
// to DPI. Upload from a real browser is sporadic and has no meaningful timing
// fingerprint. Applying 15-50ms per-frame delays to upload caps throughput at
// ~1-2.5 Mbps with zero stealth benefit.
//
// Cover traffic frames (Padding, KeepAlive) get full timing shaping so idle
// periods are filled with realistically-timed noise.
func (tw *TimerFrameWriter) WriteFrame(f *framing.Frame) error {
	// Fast path: data-carrying frames bypass timing entirely.
	if f.Type != framing.FramePadding && f.Type != framing.FrameKeepAlive {
		return tw.Next.WriteFrame(f)
	}

	tw.mu.Lock()
	mode := tw.Selector.Select(tw.byteRate, tw.streamCount)
	tw.mu.Unlock()

	if count := timerFrameCount.Add(1); count%100 == 0 {
		slog.Debug("DEBUG: timer", "mode", mode, "byteRate", tw.byteRate, "streams", tw.streamCount, "frame", count)
	}

	if mode == ModePerformance {
		return tw.Next.WriteFrame(f)
	}

	frameBytes := len(f.Payload) + len(f.Padding)

	tw.mu.Lock()
	tw.burstBytes += frameBytes
	tw.burstFrames++
	burstBytes := tw.burstBytes
	burstFrames := tw.burstFrames
	tw.mu.Unlock()

	delay := tw.Timer.Delay(burstBytes, burstFrames)
	switch mode {
	case ModeBalanced:
		delay /= 4
		if delay > maxBalancedDelay {
			delay = maxBalancedDelay
		}
	case ModeStealth:
		if delay > maxStealthDelay {
			delay = maxStealthDelay
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}

	if tw.Timer.BurstComplete(burstBytes, burstFrames) {
		pause := tw.Timer.IdleDuration()
		if mode == ModeBalanced {
			pause /= 4
		}
		if pause > 0 {
			time.Sleep(pause)
		}
		tw.mu.Lock()
		tw.burstBytes = 0
		tw.burstFrames = 0
		tw.mu.Unlock()
	}

	return tw.Next.WriteFrame(f)
}

// UpdateStats updates the current traffic statistics used by the Selector
// to determine the shaping mode.
func (tw *TimerFrameWriter) UpdateStats(byteRate int64, streamCount int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.byteRate = byteRate
	tw.streamCount = streamCount
}
