package shaping

import "strings"

// Mode defines the shaping aggressiveness level.
type Mode int

const (
	// ModeStealth applies full shaping: padding + timing + bursts.
	ModeStealth Mode = iota
	// ModeBalanced applies moderate padding with relaxed timing.
	ModeBalanced
	// ModePerformance applies minimal padding with no timing constraints.
	ModePerformance
)

// ParseMode converts a string to a Mode. Returns the mode and true
// on success, or (ModeStealth, false) for unrecognized strings.
func ParseMode(s string) (Mode, bool) {
	switch strings.ToLower(s) {
	case "performance":
		return ModePerformance, true
	case "balanced":
		return ModeBalanced, true
	case "stealth":
		return ModeStealth, true
	default:
		return ModeStealth, false
	}
}
