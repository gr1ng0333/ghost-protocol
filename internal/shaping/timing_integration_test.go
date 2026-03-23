package shaping

import (
	"sync"
	"testing"
	"time"

	"ghost/internal/framing"
)

// collectWriter records all frames written to it.
type collectWriter struct {
	mu     sync.Mutex
	frames []*framing.Frame
}

func (w *collectWriter) WriteFrame(f *framing.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, f)
	return nil
}

func (w *collectWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.frames)
}

// fixedSelector always returns the configured mode.
type fixedSelector struct {
	mode Mode
}

func (s *fixedSelector) Select(byteRate int64, streamCount int) Mode {
	return s.mode
}

func testTimingProfile() *Profile {
	return &Profile{
		Name:       "test_timing",
		SizeDist:   Distribution{Type: "uniform", Params: []float64{100, 200}},
		TimingDist: Distribution{Type: "lognormal", Params: []float64{2.0, 0.5}},
		BurstConf: BurstConfig{
			MinBurstBytes: 5000,
			MaxBurstBytes: 50000,
			MinPauseMs:    50,
			MaxPauseMs:    100,
		},
	}
}

func TestPipeline_PerformanceMode_NoDelay(t *testing.T) {
	profile, err := LoadProfile("../../profiles/chrome_browsing.json")
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	cw := &collectWriter{}
	padder := NewProfilePadder(profile, 42)
	timer := NewProfileTimer(profile, 43)

	padded := &PadderFrameWriter{Padder: padder, Next: cw}
	timed := &TimerFrameWriter{
		Timer:    timer,
		Selector: &PassthroughSelector{}, // always ModePerformance
		Next:     padded,
	}

	start := time.Now()
	for i := 0; i < 500; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 100),
		}
		if err := timed.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	if elapsed >= 200*time.Millisecond {
		t.Errorf("Performance mode took %v, want < 200ms", elapsed)
	}

	if cw.count() < 500 {
		t.Errorf("expected at least 500 frames, got %d", cw.count())
	}
}

func TestPipeline_StealthMode_HasDelay(t *testing.T) {
	profile := testTimingProfile()

	cw := &collectWriter{}
	timer := NewProfileTimer(profile, 44)

	timed := &TimerFrameWriter{
		Timer:    timer,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}
	// Set streamCount > 0 so Stealth actually applies via the selector.
	timed.UpdateStats(0, 1)

	start := time.Now()
	for i := 0; i < 5; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}
		if err := timed.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 20*time.Millisecond {
		t.Errorf("Stealth mode took %v, want >= 20ms", elapsed)
	}

	if cw.count() != 5 {
		t.Errorf("expected 5 frames, got %d", cw.count())
	}
}

func TestPipeline_AdaptiveSwitch(t *testing.T) {
	profile := testTimingProfile()

	cw := &collectWriter{}
	timer := NewProfileTimer(profile, 45)
	selector := NewAdaptiveSelector(ModeStealth, true)

	timed := &TimerFrameWriter{
		Timer:    timer,
		Selector: selector,
		Next:     cw,
	}

	// Phase 1: low byteRate, streamCount=1 → Stealth (byteRate < idleThreshold).
	timed.UpdateStats(0, 1)

	start1 := time.Now()
	for i := 0; i < 3; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}
		if err := timed.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame phase1[%d]: %v", i, err)
		}
	}
	elapsed1 := time.Since(start1)

	if elapsed1 < 10*time.Millisecond {
		t.Errorf("Stealth phase took %v, want >= 10ms", elapsed1)
	}

	// Phase 2: high byteRate → Performance (byteRate > bulkThreshold).
	timed.UpdateStats(2*1024*1024, 1)

	start2 := time.Now()
	for i := 0; i < 3; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}
		if err := timed.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame phase2[%d]: %v", i, err)
		}
	}
	elapsed2 := time.Since(start2)

	if elapsed2 >= 50*time.Millisecond {
		t.Errorf("Performance phase took %v, want < 50ms", elapsed2)
	}

	if cw.count() != 6 {
		t.Errorf("expected 6 frames total, got %d", cw.count())
	}
}

func TestPipeline_PadderAndTimer_Compose(t *testing.T) {
	profile, err := LoadProfile("../../profiles/chrome_browsing.json")
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	cw := &collectWriter{}
	padder := NewProfilePadder(profile, 46)
	timer := NewProfileTimer(profile, 47)

	padded := &PadderFrameWriter{Padder: padder, Next: cw}
	timed := &TimerFrameWriter{
		Timer:    timer,
		Selector: &PassthroughSelector{}, // Performance = no delay
		Next:     padded,
	}

	for i := 0; i < 100; i++ {
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}
		if err := timed.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}

	if cw.count() < 100 {
		t.Errorf("expected at least 100 frames, got %d", cw.count())
	}

	// Verify most frames have padding added by the padder.
	paddedCount := 0
	cw.mu.Lock()
	for _, f := range cw.frames {
		if len(f.Padding) > 0 {
			paddedCount++
		}
	}
	cw.mu.Unlock()

	if paddedCount == 0 {
		t.Error("expected some frames to have padding, got 0")
	}
}
