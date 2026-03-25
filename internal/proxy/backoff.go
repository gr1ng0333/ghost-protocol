package proxy

import (
	"math"
	"time"
)

// ExponentialBackoff computes successive delays using exponential growth
// capped at a maximum value. Safe for sequential use; not goroutine-safe.
type ExponentialBackoff struct {
	Initial    time.Duration
	Max        time.Duration
	Multiplier float64
	attempts   int
}

// Next returns the next backoff delay and advances the internal counter.
// The first call after construction or Reset returns 0 (immediate retry).
// Subsequent calls return Initial, Initial*Multiplier^1, Initial*Multiplier^2, etc.,
// capped at Max.
func (b *ExponentialBackoff) Next() time.Duration {
	if b.attempts == 0 {
		b.attempts++
		return 0
	}
	d := time.Duration(float64(b.Initial) * math.Pow(b.Multiplier, float64(b.attempts-1)))
	b.attempts++
	if d > b.Max {
		d = b.Max
	}
	return d
}

// Reset restarts the backoff sequence from the beginning.
func (b *ExponentialBackoff) Reset() {
	b.attempts = 0
}
