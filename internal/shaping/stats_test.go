package shaping

import (
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"ghost/internal/framing"
)

// chromeProfilePath returns the path to chrome_browsing.json relative
// to the package directory (go test sets cwd to the package dir).
func chromeProfilePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "profiles", "chrome_browsing.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("chrome profile not found at %s: %v", path, err)
	}
	return path
}

func TestProfilePadder_SizeDistribution(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)
	const n = 10000

	var small, medium, large int
	for i := 0; i < n; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 100),
		}
		frames := p.Pad(f)
		// Use the last frame (data frame); first may be noise.
		data := frames[len(frames)-1]
		size := headerSize + len(data.Payload) + len(data.Padding)

		switch {
		case size < 1000:
			small++
		case size <= 5000:
			medium++
		default:
			large++
		}
	}

	smallPct := float64(small) / float64(n) * 100
	mediumPct := float64(medium) / float64(n) * 100
	largePct := float64(large) / float64(n) * 100

	t.Logf("Distribution: small=%.1f%% medium=%.1f%% large=%.1f%%", smallPct, mediumPct, largePct)

	if smallPct < 5 || smallPct > 20 {
		t.Errorf("small fraction %.1f%% outside [5%%, 20%%]", smallPct)
	}
	if mediumPct < 10 || mediumPct > 35 {
		t.Errorf("medium fraction %.1f%% outside [10%%, 35%%]", mediumPct)
	}
	if largePct < 50 || largePct > 85 {
		t.Errorf("large fraction %.1f%% outside [50%%, 85%%]", largePct)
	}
}

func TestProfilePadder_KSTest(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)
	const n = 10000

	sizes := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}
		frames := p.Pad(f)
		data := frames[len(frames)-1]
		size := headerSize + len(data.Payload) + len(data.Padding)
		sizes = append(sizes, float64(size))
	}
	sort.Float64s(sizes)

	samples := prof.SizeDist.Samples // 101-point CDF

	// Compute D = max |F_empirical(x) - F_profile(x)|
	var dMax float64
	for i, x := range sizes {
		// Empirical CDF: (i+1)/n
		fEmpirical := float64(i+1) / float64(n)

		// Profile CDF: find where x falls in samples via binary search.
		fProfile := profileCDF(samples, x)

		d := math.Abs(fEmpirical - fProfile)
		if d > dMax {
			dMax = d
		}
	}

	t.Logf("KS statistic D = %.4f", dMax)
	if dMax >= 0.05 {
		t.Errorf("KS statistic D=%.4f >= 0.05 threshold", dMax)
	}
}

// profileCDF computes the CDF value for x given a sorted samples array
// representing percentiles 0 through 100 (101 entries).
func profileCDF(samples []float64, x float64) float64 {
	n := len(samples)
	if x <= samples[0] {
		return 0.0
	}
	if x >= samples[n-1] {
		return 1.0
	}

	// Binary search for the rightmost sample <= x.
	idx := sort.SearchFloat64s(samples, x)
	if idx >= n {
		return 1.0
	}
	// SearchFloat64s returns the index where x would be inserted.
	// So samples[idx-1] <= x < samples[idx] (if idx > 0).
	if idx == 0 {
		return 0.0
	}

	lo := idx - 1
	hi := idx
	// Linear interpolation between percentiles lo and hi.
	frac := (x - samples[lo]) / (samples[hi] - samples[lo])
	return (float64(lo) + frac) / float64(n-1)
}

func TestProfilePadder_NeverShrinks(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)
	rng := rand.New(rand.NewSource(99))

	for i := 0; i < 5000; i++ {
		payloadLen := 1 + rng.Intn(framing.MaxPayloadSize)
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, payloadLen),
		}
		origSize := headerSize + len(f.Payload)

		frames := p.Pad(f)
		data := frames[len(frames)-1]
		paddedSize := headerSize + len(data.Payload) + len(data.Padding)

		if paddedSize < origSize {
			t.Fatalf("frame %d: padded size %d < original %d", i, paddedSize, origSize)
		}
	}
}

func TestProfilePadder_PassthroughForLargeFrames(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)
	const n = 1000
	unchanged := 0

	for i := 0; i < n; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, framing.MaxPayloadSize),
		}
		frames := p.Pad(f)
		data := frames[len(frames)-1]
		if len(data.Padding) == 0 {
			unchanged++
		}
	}

	pct := float64(unchanged) / float64(n) * 100
	t.Logf("Large frames unchanged: %.1f%% (%d/%d)", pct, unchanged, n)
	if pct < 95 {
		t.Errorf("expected >95%% unchanged, got %.1f%%", pct)
	}
}

func TestProfilePadder_PaddingFrameInjection(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)
	const n = 10000

	totalFrames := 0
	noiseFrames := 0

	for i := 0; i < n; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 100),
		}
		frames := p.Pad(f)
		totalFrames += len(frames)

		for _, pf := range frames {
			if pf.Type == framing.FramePadding {
				noiseFrames++
				if pf.StreamID != 0 {
					t.Errorf("noise frame StreamID = %d, want 0", pf.StreamID)
				}
			}
		}
	}

	if totalFrames <= n {
		t.Errorf("expected total frames > %d, got %d", n, totalFrames)
	}

	injectionRate := float64(noiseFrames) / float64(n) * 100
	t.Logf("Noise injection: %d/%d = %.1f%%", noiseFrames, n, injectionRate)
	if injectionRate < 5 || injectionRate > 15 {
		t.Errorf("injection rate %.1f%% outside [5%%, 15%%]", injectionRate)
	}
}

func TestUnpadder_StripsPadding(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := NewProfilePadder(prof, 42)

	// Data frame with padding — Unpad should strip padding.
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 5,
		Payload:  []byte("hello"),
		Padding:  make([]byte, 200),
	}
	result := p.Unpad(f)
	if result == nil {
		t.Fatal("Unpad returned nil for data frame")
	}
	if result.Padding != nil {
		t.Errorf("Unpad should strip Padding, got len=%d", len(result.Padding))
	}
	if string(result.Payload) != "hello" {
		t.Errorf("Payload should be preserved, got %q", result.Payload)
	}

	// FramePadding — Unpad should return nil.
	noise := &framing.Frame{
		Type:     framing.FramePadding,
		StreamID: 0,
		Padding:  make([]byte, 100),
	}
	if p.Unpad(noise) != nil {
		t.Error("Unpad should return nil for FramePadding")
	}
}

func TestLoadProfile_ChromeBrowsing(t *testing.T) {
	prof, err := LoadProfile(chromeProfilePath(t))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	if prof.Name != "chrome_browsing" {
		t.Errorf("Name: want %q, got %q", "chrome_browsing", prof.Name)
	}
	if prof.SizeDist.Type != "empirical" {
		t.Errorf("SizeDist.Type: want %q, got %q", "empirical", prof.SizeDist.Type)
	}
	if len(prof.SizeDist.Samples) != 101 {
		t.Fatalf("SizeDist.Samples length: want 101, got %d", len(prof.SizeDist.Samples))
	}
	if prof.SizeDist.Samples[0] <= 0 {
		t.Errorf("Samples[0] should be > 0, got %f", prof.SizeDist.Samples[0])
	}
	if prof.SizeDist.Samples[100] != 16384 {
		t.Errorf("Samples[100]: want 16384, got %f", prof.SizeDist.Samples[100])
	}

	// Verify samples are sorted ascending.
	for i := 1; i < len(prof.SizeDist.Samples); i++ {
		if prof.SizeDist.Samples[i] < prof.SizeDist.Samples[i-1] {
			t.Errorf("Samples not sorted at index %d: %f < %f",
				i, prof.SizeDist.Samples[i], prof.SizeDist.Samples[i-1])
			break
		}
	}
}

func TestLoadProfile_InvalidPath(t *testing.T) {
	_, err := LoadProfile("/nonexistent/path/profile.json")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}
