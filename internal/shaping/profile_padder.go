package shaping

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"

	"ghost/internal/framing"
)

// headerSize is the fixed overhead of a serialized Ghost frame:
// Type(1) + StreamID(4) + PayloadLen(2) = 7 bytes.
const headerSize = 7

// maxFrameSize is the maximum total serialized frame size.
const maxFrameSize = framing.MaxPayloadSize + headerSize

// minFrameSize is the minimum meaningful serialized frame size
// (header plus at least one byte of content).
const minFrameSize = headerSize + 1

// ProfilePadder implements the Padder interface using a traffic Profile
// to determine padding sizes via statistical distribution sampling.
type ProfilePadder struct {
	profile   *Profile
	rng       *rand.Rand
	noiseProb float64 // per-session randomized noise injection probability
}

// NewProfilePadder creates a ProfilePadder with the given profile and
// a deterministic RNG seeded with seed.
func NewProfilePadder(profile *Profile, seed int64) *ProfilePadder {
	rng := rand.New(rand.NewSource(seed))
	return &ProfilePadder{
		profile:   profile,
		rng:       rng,
		noiseProb: 0.05 + rng.Float64()*0.10, // randomize between 5% and 15%
	}
}

// Pad adjusts the frame's padding to match the target size sampled from
// the profile's size distribution. If the profile has a populated BurstConf,
// there is a 10% chance a noise FramePadding frame is injected before the
// data frame. Pad never shrinks a frame.
func (p *ProfilePadder) Pad(f *framing.Frame) []*framing.Frame {
	currentSize := headerSize + len(f.Payload) + len(f.Padding)
	target := p.sampleSize()

	if target > currentSize {
		extra := target - currentSize
		f.Padding = append(f.Padding, make([]byte, extra)...)
	}

	// Possibly inject a noise padding frame before the data frame.
	if p.hasBurstConf() && p.rng.Float64() < p.noiseProb {
		noiseSize := p.sampleSize()
		noisePadLen := noiseSize - headerSize
		if noisePadLen < 0 {
			noisePadLen = 0
		}
		noise := &framing.Frame{
			Type:     framing.FramePadding,
			StreamID: 0,
			Padding:  make([]byte, noisePadLen),
		}
		return []*framing.Frame{noise, f}
	}

	return []*framing.Frame{f}
}

// Unpad strips padding from a frame. Returns nil for pure padding frames
// (FramePadding type), causing them to be discarded by the receiver.
func (p *ProfilePadder) Unpad(f *framing.Frame) *framing.Frame {
	if f.Type == framing.FramePadding {
		return nil
	}
	f.Padding = nil
	return f
}

// sampleSize returns a target serialized frame size sampled from the
// profile's size distribution, clamped to [minFrameSize, maxFrameSize].
func (p *ProfilePadder) sampleSize() int {
	var raw float64

	switch p.profile.SizeDist.Type {
	case "lognormal":
		mu := p.profile.SizeDist.Params[0]
		sigma := p.profile.SizeDist.Params[1]
		raw = math.Exp(mu + sigma*p.rng.NormFloat64())

	case "pareto":
		xm := p.profile.SizeDist.Params[0]
		alpha := p.profile.SizeDist.Params[1]
		raw = xm * math.Pow(1-p.rng.Float64(), -1.0/alpha)

	case "uniform":
		lo := p.profile.SizeDist.Params[0]
		hi := p.profile.SizeDist.Params[1]
		raw = lo + p.rng.Float64()*(hi-lo)

	case "empirical":
		raw = p.sampleEmpirical()

	default:
		raw = float64(minFrameSize)
	}

	// Clamp and round.
	size := int(math.Round(raw))
	if size < minFrameSize {
		size = minFrameSize
	}
	if size > maxFrameSize {
		size = maxFrameSize
	}
	return size
}

// sampleEmpirical samples from the empirical CDF defined by Samples
// (sorted ascending) using linear interpolation.
func (p *ProfilePadder) sampleEmpirical() float64 {
	samples := p.profile.SizeDist.Samples
	if len(samples) == 0 {
		return float64(minFrameSize)
	}

	// Treat samples as sorted CDF breakpoints.
	u := p.rng.Float64()
	n := len(samples)
	pos := u * float64(n-1)
	idx := int(pos)
	frac := pos - float64(idx)

	if idx >= n-1 {
		return samples[n-1]
	}
	return samples[idx] + frac*(samples[idx+1]-samples[idx])
}

// hasBurstConf reports whether the profile has a non-zero burst configuration.
func (p *ProfilePadder) hasBurstConf() bool {
	bc := p.profile.BurstConf
	return bc.MinBurstBytes > 0 || bc.MaxBurstBytes > 0
}

// LoadProfile reads a Profile from the JSON file at path and validates
// that the size distribution type is supported.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}
	return parseProfile(data)
}

// parseProfile unmarshals and validates a Profile from raw JSON bytes.
func parseProfile(data []byte) (*Profile, error) {
	var prof Profile
	if err := json.Unmarshal(data, &prof); err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}

	supported := map[string]bool{
		"lognormal": true,
		"pareto":    true,
		"uniform":   true,
		"empirical": true,
	}
	if !supported[prof.SizeDist.Type] {
		return nil, fmt.Errorf("load profile: unsupported size distribution type %q", prof.SizeDist.Type)
	}

	// Sort empirical samples for CDF interpolation.
	if prof.SizeDist.Type == "empirical" {
		sort.Float64s(prof.SizeDist.Samples)
	}

	return &prof, nil
}

// PadderFrameWriter wraps a Padder and a downstream FrameWriter.
// Each WriteFrame call pads the frame and forwards the result(s) to Next.
type PadderFrameWriter struct {
	Padder Padder
	Next   framing.FrameWriter
}

// WriteFrame pads the frame and writes all resulting frames to Next.
func (pw *PadderFrameWriter) WriteFrame(f *framing.Frame) error {
	frames := pw.Padder.Pad(f)
	for _, pf := range frames {
		if err := pw.Next.WriteFrame(pf); err != nil {
			return fmt.Errorf("padder write: %w", err)
		}
	}
	return nil
}

// UnpadderFrameReader wraps a Padder and an upstream FrameReader.
// It reads frames from Src, strips padding, and silently discards
// pure padding frames (FramePadding type).
type UnpadderFrameReader struct {
	Padder Padder
	Src    framing.FrameReader
}

// ReadFrame reads frames from Src until a non-padding frame is found,
// strips its padding, and returns it.
func (ur *UnpadderFrameReader) ReadFrame() (*framing.Frame, error) {
	for {
		f, err := ur.Src.ReadFrame()
		if err != nil {
			return nil, err
		}
		result := ur.Padder.Unpad(f)
		if result != nil {
			return result, nil
		}
		// skip pure padding frames, loop again
	}
}
