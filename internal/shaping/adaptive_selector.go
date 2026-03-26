package shaping

import "sync/atomic"

// AdaptiveSelector chooses the shaping mode based on current traffic
// characteristics. In auto mode, it dynamically switches between
// Stealth, Balanced, and Performance based on byte rate and stream count.
// When auto mode is disabled, it always returns the configured default mode.
type AdaptiveSelector struct {
	defaultMode Mode
	autoMode    bool

	// Thresholds for automatic mode selection (bytes per second).
	bulkThreshold int64 // above this → Performance (default: 1MB/s)
	idleThreshold int64 // below this → Stealth (default: 10KB/s)

	// lastMode caches the most recently computed mode so that components
	// like PadderFrameWriter can query it without calling Select().
	lastMode atomic.Int32
}

// NewAdaptiveSelector creates an AdaptiveSelector.
// defaultMode is used when autoMode is false.
// autoMode enables dynamic mode switching based on traffic.
func NewAdaptiveSelector(defaultMode Mode, autoMode bool) *AdaptiveSelector {
	s := &AdaptiveSelector{
		defaultMode:   defaultMode,
		autoMode:      autoMode,
		bulkThreshold: 200 * 1024, // 200 KB/s — reachable in balanced mode
		idleThreshold: 10 * 1024,  // 10 KB/s
	}
	s.lastMode.Store(int32(defaultMode))
	return s
}

// Select returns the appropriate Mode for current traffic.
func (s *AdaptiveSelector) Select(byteRate int64, streamCount int) Mode {
	if !s.autoMode {
		s.lastMode.Store(int32(s.defaultMode))
		return s.defaultMode
	}

	var mode Mode
	switch {
	case streamCount == 0:
		mode = ModeStealth
	case byteRate > s.bulkThreshold:
		mode = ModePerformance
	case byteRate < s.idleThreshold:
		mode = ModeStealth
	default:
		mode = ModeBalanced
	}

	s.lastMode.Store(int32(mode))
	return mode
}

// CurrentMode returns the last mode computed by Select, safe for
// concurrent readers like PadderFrameWriter.
func (s *AdaptiveSelector) CurrentMode() Mode {
	return Mode(s.lastMode.Load())
}

// SetThresholds configures the byte-rate thresholds for mode switching.
// bulkBytesPerSec: above this → Performance. idleBytesPerSec: below this → Stealth.
func (s *AdaptiveSelector) SetThresholds(bulkBytesPerSec, idleBytesPerSec int64) {
	s.bulkThreshold = bulkBytesPerSec
	s.idleThreshold = idleBytesPerSec
}
