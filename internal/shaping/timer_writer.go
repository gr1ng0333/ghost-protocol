package shaping

import (
	"sync"
	"time"

	"ghost/internal/framing"
)

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
// In Performance mode, no delay is applied (true passthrough).
// In Balanced mode, delays are reduced to 1/4 and burst pauses to 1/4.
// In Stealth mode, full delays with a cap to trim heavy-tail outliers.
func (tw *TimerFrameWriter) WriteFrame(f *framing.Frame) error {
	tw.mu.Lock()
	mode := tw.Selector.Select(tw.byteRate, tw.streamCount)
	tw.mu.Unlock()

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
