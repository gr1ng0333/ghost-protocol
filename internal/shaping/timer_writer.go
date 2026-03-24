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

// WriteFrame applies timing shaping and forwards the frame to Next.
// In Performance mode, no delay is applied. Otherwise, the Timer's
// Delay is applied before writing, and burst boundaries trigger pauses.
func (tw *TimerFrameWriter) WriteFrame(f *framing.Frame) error {
	tw.mu.Lock()
	mode := tw.Selector.Select(tw.byteRate, tw.streamCount)
	tw.mu.Unlock()

	if mode != ModePerformance {
		frameBytes := len(f.Payload) + len(f.Padding)

		tw.mu.Lock()
		tw.burstBytes += frameBytes
		tw.burstFrames++
		burstBytes := tw.burstBytes
		burstFrames := tw.burstFrames
		tw.mu.Unlock()

		delay := tw.Timer.Delay(burstBytes, burstFrames)
		if mode == ModeBalanced {
			delay /= 2
		}
		if delay > 0 {
			time.Sleep(delay)
		}

		if tw.Timer.BurstComplete(burstBytes, burstFrames) {
			pause := tw.Timer.IdleDuration()
			if pause > 0 {
				time.Sleep(pause)
			}
			tw.mu.Lock()
			tw.burstBytes = 0
			tw.burstFrames = 0
			tw.mu.Unlock()
		}
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
