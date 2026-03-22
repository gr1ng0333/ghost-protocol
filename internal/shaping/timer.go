package shaping

import "time"

// Timer controls inter-frame timing to match a target profile.
type Timer interface {
	// Delay returns how long to wait before sending the next frame.
	Delay(totalBytes int, frameCount int) time.Duration
	// BurstComplete reports whether the current burst is finished.
	BurstComplete(totalBytes int, frameCount int) bool
	// IdleDuration returns the delay to insert during idle periods.
	IdleDuration() time.Duration
}
