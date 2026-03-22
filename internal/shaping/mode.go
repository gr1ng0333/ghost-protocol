package shaping

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
