package shaping

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
}

// NewAdaptiveSelector creates an AdaptiveSelector.
// defaultMode is used when autoMode is false.
// autoMode enables dynamic mode switching based on traffic.
func NewAdaptiveSelector(defaultMode Mode, autoMode bool) *AdaptiveSelector {
	return &AdaptiveSelector{
		defaultMode:   defaultMode,
		autoMode:      autoMode,
		bulkThreshold: 200 * 1024, // 200 KB/s — reachable in balanced mode
		idleThreshold: 10 * 1024,  // 10 KB/s
	}
}

// Select returns the appropriate Mode for current traffic.
func (s *AdaptiveSelector) Select(byteRate int64, streamCount int) Mode {
	if !s.autoMode {
		return s.defaultMode
	}

	// No active streams → full stealth.
	if streamCount == 0 {
		return ModeStealth
	}

	// High throughput → bypass shaping for performance.
	if byteRate > s.bulkThreshold {
		return ModePerformance
	}

	// Low throughput → full stealth.
	if byteRate < s.idleThreshold {
		return ModeStealth
	}

	// Moderate throughput → balanced.
	return ModeBalanced
}

// SetThresholds configures the byte-rate thresholds for mode switching.
// bulkBytesPerSec: above this → Performance. idleBytesPerSec: below this → Stealth.
func (s *AdaptiveSelector) SetThresholds(bulkBytesPerSec, idleBytesPerSec int64) {
	s.bulkThreshold = bulkBytesPerSec
	s.idleThreshold = idleBytesPerSec
}
