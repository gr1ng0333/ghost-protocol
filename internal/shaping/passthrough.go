package shaping

import (
	"time"

	"ghost/internal/framing"
)

// PassthroughPadder returns frames unmodified (no padding).
type PassthroughPadder struct{}

// Pad returns the frame unchanged in a single-element slice.
func (p *PassthroughPadder) Pad(f *framing.Frame) []*framing.Frame {
	return []*framing.Frame{f}
}

// Unpad returns the frame unchanged, or nil if it is a padding frame.
func (p *PassthroughPadder) Unpad(f *framing.Frame) *framing.Frame {
	if f.Type == framing.FramePadding {
		return nil
	}
	return f
}

// PassthroughTimer returns zero delay (no timing shaping).
type PassthroughTimer struct{}

// Delay always returns 0 (no inter-frame delay).
func (t *PassthroughTimer) Delay(totalBytes, frameCount int) time.Duration {
	return 0
}

// BurstComplete always returns false (no burst segmentation).
func (t *PassthroughTimer) BurstComplete(totalBytes, frameCount int) bool {
	return false
}

// IdleDuration always returns 0 (no idle padding).
func (t *PassthroughTimer) IdleDuration() time.Duration {
	return 0
}

// PassthroughSelector always returns ModePerformance.
type PassthroughSelector struct{}

// Select always returns ModePerformance regardless of traffic characteristics.
func (s *PassthroughSelector) Select(byteRate int64, streamCount int) Mode {
	return ModePerformance
}
