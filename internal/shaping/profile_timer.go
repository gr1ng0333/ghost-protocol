package shaping

import (
	"math"
	"math/rand"
	"time"
)

// ProfileTimer implements the Timer interface using a traffic Profile
// to sample inter-frame delays and determine burst boundaries.
type ProfileTimer struct {
	profile *Profile
	rng     *rand.Rand
}

// NewProfileTimer creates a ProfileTimer with the given profile and
// a deterministic RNG seeded with seed.
func NewProfileTimer(profile *Profile, seed int64) *ProfileTimer {
	return &ProfileTimer{
		profile: profile,
		rng:     rand.New(rand.NewSource(seed)),
	}
}

// Delay returns the inter-frame delay sampled from the profile's timing
// distribution. The sampled value is interpreted as milliseconds.
func (pt *ProfileTimer) Delay(totalBytes, frameCount int) time.Duration {
	ms := pt.sampleTiming()
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// BurstComplete reports whether the current burst has reached its byte
// limit as defined by the profile's burst configuration.
func (pt *ProfileTimer) BurstComplete(totalBytes, frameCount int) bool {
	bc := pt.profile.BurstConf
	if bc.MaxBurstBytes <= 0 {
		return false
	}
	return totalBytes >= bc.MaxBurstBytes
}

// IdleDuration returns a random pause duration between bursts, sampled
// uniformly from [MinPauseMs, MaxPauseMs) in the profile's burst config.
func (pt *ProfileTimer) IdleDuration() time.Duration {
	bc := pt.profile.BurstConf
	if bc.MaxPauseMs <= 0 {
		return 0
	}
	lo := bc.MinPauseMs
	hi := bc.MaxPauseMs
	if hi <= lo {
		return time.Duration(lo) * time.Millisecond
	}
	pause := lo + pt.rng.Intn(hi-lo)
	return time.Duration(pause) * time.Millisecond
}

// Reset resets the timer's internal burst tracking state.
func (pt *ProfileTimer) Reset() {
	// ProfileTimer is stateless with respect to bursts; burst state is
	// tracked by TimerFrameWriter. This is a no-op.
}

// sampleTiming returns a raw timing sample in milliseconds from the
// profile's timing distribution.
func (pt *ProfileTimer) sampleTiming() float64 {
	td := pt.profile.TimingDist
	switch td.Type {
	case "lognormal":
		if len(td.Params) < 2 {
			return 0
		}
		mu := td.Params[0]
		sigma := td.Params[1]
		return math.Exp(mu + sigma*pt.rng.NormFloat64())
	case "uniform":
		if len(td.Params) < 2 {
			return 0
		}
		lo := td.Params[0]
		hi := td.Params[1]
		return lo + pt.rng.Float64()*(hi-lo)
	case "pareto":
		if len(td.Params) < 2 {
			return 0
		}
		xm := td.Params[0]
		alpha := td.Params[1]
		return xm * math.Pow(1-pt.rng.Float64(), -1.0/alpha)
	default:
		return 0
	}
}
