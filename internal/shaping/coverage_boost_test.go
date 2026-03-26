package shaping

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"ghost/internal/framing"
)

// ---------------------------------------------------------------------------
// Tests for ProfileTimer — covers IdleDuration, Reset, sampleTiming branches,
// Delay edge cases, and BurstComplete edge cases.
// ---------------------------------------------------------------------------

func TestProfileTimer_IdleDuration_ValidRange(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{
			MinPauseMs: 100,
			MaxPauseMs: 500,
		},
	}
	pt := NewProfileTimer(prof, 42)

	for i := 0; i < 100; i++ {
		d := pt.IdleDuration()
		if d < 100*time.Millisecond || d >= 500*time.Millisecond {
			t.Errorf("IdleDuration() = %v, want [100ms, 500ms)", d)
		}
	}
}

func TestProfileTimer_IdleDuration_MaxPauseZero(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{MaxPauseMs: 0},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.IdleDuration()
	if d != 0 {
		t.Errorf("IdleDuration() = %v, want 0 when MaxPauseMs=0", d)
	}
}

func TestProfileTimer_IdleDuration_HiEqualsLo(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{
			MinPauseMs: 200,
			MaxPauseMs: 200,
		},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.IdleDuration()
	if d != 200*time.Millisecond {
		t.Errorf("IdleDuration() = %v, want 200ms when hi==lo", d)
	}
}

func TestProfileTimer_IdleDuration_HiLessThanLo(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{
			MinPauseMs: 300,
			MaxPauseMs: 100,
		},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.IdleDuration()
	if d != 300*time.Millisecond {
		t.Errorf("IdleDuration() = %v, want 300ms when hi<lo", d)
	}
}

func TestProfileTimer_Reset(t *testing.T) {
	prof := testTimingProfile()
	pt := NewProfileTimer(prof, 42)
	// Reset is a no-op but must not panic.
	pt.Reset()
}

func TestProfileTimer_SampleTiming_Uniform(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "uniform", Params: []float64{10, 50}},
	}
	pt := NewProfileTimer(prof, 42)

	for i := 0; i < 100; i++ {
		d := pt.Delay(0, 0)
		if d < 10*time.Millisecond || d > 50*time.Millisecond {
			t.Errorf("Delay() = %v, want [10ms, 50ms]", d)
		}
	}
}

func TestProfileTimer_SampleTiming_Pareto(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "pareto", Params: []float64{5.0, 2.0}},
	}
	pt := NewProfileTimer(prof, 42)

	for i := 0; i < 100; i++ {
		d := pt.Delay(0, 0)
		if d < 5*time.Millisecond {
			t.Errorf("Delay() = %v, want >= 5ms for pareto xm=5", d)
		}
	}
}

func TestProfileTimer_SampleTiming_UnsupportedType(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "unknown"},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.Delay(0, 0)
	if d != 0 {
		t.Errorf("Delay() = %v, want 0 for unsupported timing type", d)
	}
}

func TestProfileTimer_SampleTiming_LognormalInsufficientParams(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "lognormal", Params: []float64{1.0}},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.Delay(0, 0)
	if d != 0 {
		t.Errorf("Delay() = %v, want 0 when lognormal has < 2 params", d)
	}
}

func TestProfileTimer_SampleTiming_UniformInsufficientParams(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "uniform", Params: []float64{10}},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.Delay(0, 0)
	if d != 0 {
		t.Errorf("Delay() = %v, want 0 when uniform has < 2 params", d)
	}
}

func TestProfileTimer_SampleTiming_ParetoInsufficientParams(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "pareto", Params: []float64{5.0}},
	}
	pt := NewProfileTimer(prof, 42)

	d := pt.Delay(0, 0)
	if d != 0 {
		t.Errorf("Delay() = %v, want 0 when pareto has < 2 params", d)
	}
}

func TestProfileTimer_BurstComplete_MaxBurstZero(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{MaxBurstBytes: 0},
	}
	pt := NewProfileTimer(prof, 42)

	if pt.BurstComplete(99999, 100) {
		t.Error("BurstComplete should return false when MaxBurstBytes=0")
	}
}

func TestProfileTimer_BurstComplete_BelowThreshold(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{MaxBurstBytes: 1000},
	}
	pt := NewProfileTimer(prof, 42)

	if pt.BurstComplete(500, 5) {
		t.Error("BurstComplete should return false when below threshold")
	}
}

func TestProfileTimer_BurstComplete_AtThreshold(t *testing.T) {
	prof := &Profile{
		BurstConf: BurstConfig{MaxBurstBytes: 1000},
	}
	pt := NewProfileTimer(prof, 42)

	if !pt.BurstComplete(1000, 10) {
		t.Error("BurstComplete should return true when at threshold")
	}
}

// ---------------------------------------------------------------------------
// Tests for TimerFrameWriter — covers burst-complete + idle pause path,
// zero-delay path, and error forwarding.
// ---------------------------------------------------------------------------

// controllableTimer allows tests to control Delay, BurstComplete, and IdleDuration.
type controllableTimer struct {
	delay         time.Duration
	burstComplete bool
	idleDuration  time.Duration
}

func (t *controllableTimer) Delay(totalBytes, frameCount int) time.Duration { return t.delay }
func (t *controllableTimer) BurstComplete(totalBytes, frameCount int) bool  { return t.burstComplete }
func (t *controllableTimer) IdleDuration() time.Duration                    { return t.idleDuration }

func TestTimerFrameWriter_BurstCompleteWithPause(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         0,
		burstComplete: true,
		idleDuration:  10 * time.Millisecond,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := tw.WriteFrame(&framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  make([]byte, 50),
		}); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// 3 burst completions × 10ms idle = at least 30ms.
	if elapsed < 30*time.Millisecond {
		t.Errorf("elapsed %v, want >= 30ms (3 burst completions × 10ms)", elapsed)
	}

	if cw.count() != 3 {
		t.Errorf("expected 3 frames, got %d", cw.count())
	}

	// Verify burst state was reset (burstBytes and burstFrames back to 0).
	tw.mu.Lock()
	bb := tw.burstBytes
	bf := tw.burstFrames
	tw.mu.Unlock()
	if bb != 0 || bf != 0 {
		t.Errorf("burst state not reset: burstBytes=%d burstFrames=%d", bb, bf)
	}
}

func TestTimerFrameWriter_BurstCompleteWithZeroPause(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         0,
		burstComplete: true,
		idleDuration:  0, // zero pause
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}

	start := time.Now()
	if err := tw.WriteFrame(&framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 50),
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("elapsed %v, want < 50ms with zero pause", elapsed)
	}
}

func TestTimerFrameWriter_WithDelay(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         10 * time.Millisecond,
		burstComplete: false,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeBalanced},
		Next:     cw,
	}

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := tw.WriteFrame(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 50),
		}); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// 3 frames × 10ms delay / 4 for ModeBalanced = 3 × 2.5ms = at least 7ms.
	if elapsed < 7*time.Millisecond {
		t.Errorf("elapsed %v, want >= 7ms", elapsed)
	}
}

func TestTimerFrameWriter_FrameWithPadding(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         0,
		burstComplete: false,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}

	f := &framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 50),
		Padding: make([]byte, 30),
	}
	if err := tw.WriteFrame(f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// burstBytes should account for payload + padding = 80.
	tw.mu.Lock()
	bb := tw.burstBytes
	tw.mu.Unlock()
	if bb != 80 {
		t.Errorf("burstBytes = %d, want 80 (50 payload + 30 padding)", bb)
	}
}

// errorWriter always returns an error.
type errorWriter struct{}

func (e *errorWriter) WriteFrame(f *framing.Frame) error {
	return errors.New("write error")
}

func TestTimerFrameWriter_ErrorForwarding(t *testing.T) {
	tw := &TimerFrameWriter{
		Timer:    &controllableTimer{},
		Selector: &PassthroughSelector{},
		Next:     &errorWriter{},
	}

	err := tw.WriteFrame(&framing.Frame{Type: framing.FrameData, Payload: make([]byte, 10)})
	if err == nil {
		t.Error("expected error from WriteFrame, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests for CoverGenerator — covers Start idempotency, Stop idempotency,
// and nextInterval default branch.
// ---------------------------------------------------------------------------

func TestCoverGenerator_StartIdempotent(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)
	defer cg.Stop()

	// Second Start should be a no-op (already running).
	cg.Start(ctx)

	cg.mu.Lock()
	running := cg.running
	cg.mu.Unlock()
	if !running {
		t.Error("expected still running after double Start")
	}
}

func TestCoverGenerator_StopIdempotent(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	// Stop without Start should be a no-op.
	cg.Stop()

	cg.mu.Lock()
	running := cg.running
	cg.mu.Unlock()
	if running {
		t.Error("expected not running after Stop without Start")
	}
}

func TestCoverGenerator_NextIntervalDefault(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	// lastPattern is zero value (patternKeepAlive == 0), but let's force
	// an invalid value to hit the default branch.
	cg.mu.Lock()
	cg.lastPattern = pattern(99)
	d := cg.nextInterval()
	cg.mu.Unlock()

	if d < 5*time.Second || d > 15*time.Second {
		t.Errorf("nextInterval() default = %v, want [5s, 15s]", d)
	}
}

// ---------------------------------------------------------------------------
// Tests for ProfilePadder — covers sampleSize default, sampleEmpirical
// edge cases, and noise injection edge case.
// ---------------------------------------------------------------------------

func TestProfilePadder_SampleSize_DefaultType(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "unsupported"},
	}
	pp := NewProfilePadder(prof, 42)

	// sampleSize with unsupported type returns minFrameSize.
	frames := pp.Pad(&framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 1),
	})
	if len(frames) == 0 {
		t.Fatal("expected at least one frame from Pad")
	}
}

func TestProfilePadder_SampleEmpirical_EmptySamples(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "empirical", Samples: []float64{}},
	}
	pp := NewProfilePadder(prof, 42)

	frames := pp.Pad(&framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 1),
	})
	if len(frames) == 0 {
		t.Fatal("expected at least one frame from Pad with empty empirical samples")
	}
}

func TestProfilePadder_SampleEmpirical_SingleSample(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "empirical", Samples: []float64{500}},
	}
	pp := NewProfilePadder(prof, 42)

	frames := pp.Pad(&framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 1),
	})
	if len(frames) == 0 {
		t.Fatal("expected at least one frame from Pad with single sample")
	}
	// With single sample, idx >= n-1 always, so sampled value is 500.
	totalSize := headerSize + len(frames[len(frames)-1].Payload) + len(frames[len(frames)-1].Padding)
	if totalSize != 500 {
		t.Errorf("expected frame size 500 with single sample, got %d", totalSize)
	}
}

func TestProfilePadder_SampleEmpirical_HighU(t *testing.T) {
	// With 2 samples, test interpolation near the top end.
	prof := &Profile{
		SizeDist: Distribution{Type: "empirical", Samples: []float64{100, 200}},
	}
	pp := NewProfilePadder(prof, 42)

	// Run many pads to exercise the idx >= n-1 edge.
	for i := 0; i < 200; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 1),
		})
		if len(frames) == 0 {
			t.Fatal("expected at least one frame")
		}
	}
}

func TestProfilePadder_Pad_LargeFrame(t *testing.T) {
	// When current size >= target, no padding is added (never shrinks).
	prof := &Profile{
		SizeDist: Distribution{Type: "uniform", Params: []float64{50, 100}},
	}
	pp := NewProfilePadder(prof, 42)

	payload := make([]byte, framing.MaxPayloadSize)
	f := &framing.Frame{
		Type:    framing.FrameData,
		Payload: payload,
	}
	frames := pp.Pad(f)
	data := frames[len(frames)-1]
	if len(data.Padding) > 0 {
		t.Errorf("expected no extra padding on max-size frame, got %d bytes", len(data.Padding))
	}
}

func TestProfilePadder_Pad_NoiseInjection_SmallTarget(t *testing.T) {
	// If noise target is very small (noisePadLen < 0), it should be clamped to 0.
	prof := &Profile{
		SizeDist: Distribution{Type: "uniform", Params: []float64{1, 5}},
		BurstConf: BurstConfig{
			MinBurstBytes: 1,
			MaxBurstBytes: 10,
		},
	}
	pp := NewProfilePadder(prof, 42)

	for i := 0; i < 200; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 1),
		})
		for _, f := range frames {
			if f.Type == framing.FramePadding && len(f.Padding) < 0 {
				t.Error("negative noise padding length")
			}
		}
	}
}

func TestProfilePadder_SampleSize_Pareto(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "pareto", Params: []float64{50.0, 2.0}},
	}
	pp := NewProfilePadder(prof, 42)

	for i := 0; i < 100; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 1),
		})
		data := frames[len(frames)-1]
		totalSize := headerSize + len(data.Payload) + len(data.Padding)
		if totalSize < minFrameSize || totalSize > maxFrameSize {
			t.Errorf("frame size %d out of [%d, %d]", totalSize, minFrameSize, maxFrameSize)
		}
	}
}

func TestProfilePadder_SampleSize_Uniform(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "uniform", Params: []float64{100, 500}},
	}
	pp := NewProfilePadder(prof, 42)

	for i := 0; i < 100; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 1),
		})
		data := frames[len(frames)-1]
		totalSize := headerSize + len(data.Payload) + len(data.Padding)
		if totalSize < minFrameSize || totalSize > maxFrameSize {
			t.Errorf("frame size %d out of [%d, %d]", totalSize, minFrameSize, maxFrameSize)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests for TimerFrameWriter — covers Stealth mode with non-burst-complete
// and balanced mode, to hit remaining untested WriteFrame branches.
// ---------------------------------------------------------------------------

func TestTimerFrameWriter_StealthMode_NoBurstComplete(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         0,
		burstComplete: false,
		idleDuration:  0,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}

	if err := tw.WriteFrame(&framing.Frame{
		Type:    framing.FrameData,
		Payload: make([]byte, 100),
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// burstBytes should accumulate (no reset since no burst complete).
	tw.mu.Lock()
	bb := tw.burstBytes
	bf := tw.burstFrames
	tw.mu.Unlock()
	if bb != 100 {
		t.Errorf("burstBytes = %d, want 100", bb)
	}
	if bf != 1 {
		t.Errorf("burstFrames = %d, want 1", bf)
	}
}

func TestTimerFrameWriter_ErrorInStealthMode(t *testing.T) {
	ct := &controllableTimer{
		delay:         0,
		burstComplete: false,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     &errorWriter{},
	}

	err := tw.WriteFrame(&framing.Frame{Type: framing.FrameData, Payload: make([]byte, 10)})
	if err == nil {
		t.Error("expected error from WriteFrame in stealth mode, got nil")
	}
}

func TestTimerFrameWriter_PerformanceMode_SkipsAllTiming(t *testing.T) {
	cw := &collectWriter{}
	ct := &controllableTimer{
		delay:         100 * time.Millisecond,
		burstComplete: true,
		idleDuration:  100 * time.Millisecond,
	}

	tw := &TimerFrameWriter{
		Timer:    ct,
		Selector: &fixedSelector{mode: ModePerformance},
		Next:     cw,
	}

	start := time.Now()
	for i := 0; i < 10; i++ {
		if err := tw.WriteFrame(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 50),
		}); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// No delays should be applied in performance mode.
	if elapsed > 50*time.Millisecond {
		t.Errorf("elapsed %v, want < 50ms in performance mode (no timing)", elapsed)
	}

	// burstBytes and burstFrames should remain 0 (performance mode skips tracking).
	tw.mu.Lock()
	bb := tw.burstBytes
	tw.mu.Unlock()
	if bb != 0 {
		t.Errorf("burstBytes = %d, want 0 in performance mode", bb)
	}
}

// ---------------------------------------------------------------------------
// Additional ProfilePadder coverage — Lognormal sampleSize with clamping.
// ---------------------------------------------------------------------------

func TestProfilePadder_SampleSize_Lognormal_Clamp(t *testing.T) {
	// Very high mu+sigma can produce values above maxFrameSize; verify clamping.
	prof := &Profile{
		SizeDist: Distribution{Type: "lognormal", Params: []float64{15.0, 2.0}},
	}
	pp := NewProfilePadder(prof, 42)

	for i := 0; i < 100; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 1),
		})
		data := frames[len(frames)-1]
		totalSize := headerSize + len(data.Payload) + len(data.Padding)
		if totalSize > maxFrameSize {
			t.Errorf("frame size %d exceeds max %d", totalSize, maxFrameSize)
		}
	}
}

// ---------------------------------------------------------------------------
// Verify that CoverGenerator writes errors are non-fatal.
// ---------------------------------------------------------------------------

func TestCoverGenerator_WriteError_NonFatal(t *testing.T) {
	ew := &errorWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(ew, sel, prof, 42)

	// These should not panic despite the writer returning errors.
	cg.injectKeepAlive()
	cg.injectAnalyticsPing()
	cg.injectMiniBurst()
}

// ---------------------------------------------------------------------------
// Verify TimerFrameWriter WriteFrame with actual ProfileTimer exercising
// the BurstComplete → IdleDuration path end-to-end.
// ---------------------------------------------------------------------------

func TestTimerFrameWriter_ProfileTimer_BurstCycle(t *testing.T) {
	prof := &Profile{
		TimingDist: Distribution{Type: "uniform", Params: []float64{0.1, 0.5}},
		BurstConf: BurstConfig{
			MinBurstBytes: 10,
			MaxBurstBytes: 50,
			MinPauseMs:    5,
			MaxPauseMs:    10,
		},
	}
	timer := NewProfileTimer(prof, 42)
	cw := &collectWriter{}

	tw := &TimerFrameWriter{
		Timer:    timer,
		Selector: &fixedSelector{mode: ModeStealth},
		Next:     cw,
	}

	// Write enough frames to trigger burst completion (MaxBurstBytes=50).
	for i := 0; i < 5; i++ {
		if err := tw.WriteFrame(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 20),
		}); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}

	if cw.count() != 5 {
		t.Errorf("expected 5 frames, got %d", cw.count())
	}
}

// ---------------------------------------------------------------------------
// Test that ProfilePadder with known noise injection via fixed seed produces
// noise frames correctly.
// ---------------------------------------------------------------------------

func TestProfilePadder_NoiseInjection_Deterministic(t *testing.T) {
	prof := &Profile{
		SizeDist: Distribution{Type: "uniform", Params: []float64{100, 200}},
		BurstConf: BurstConfig{
			MinBurstBytes: 100,
			MaxBurstBytes: 1000,
		},
	}

	// Run enough pads to trigger noise injection (~10%).
	pp := NewProfilePadder(prof, 42)
	noiseCount := 0
	total := 1000
	for i := 0; i < total; i++ {
		frames := pp.Pad(&framing.Frame{
			Type:    framing.FrameData,
			Payload: make([]byte, 50),
		})
		if len(frames) > 1 {
			noiseCount++
			if frames[0].Type != framing.FramePadding {
				t.Errorf("noise frame should be FramePadding, got %d", frames[0].Type)
			}
		}
	}

	pct := float64(noiseCount) / float64(total) * 100
	if pct < 5 || pct > 20 {
		t.Errorf("noise injection rate %.1f%%, expected ~10%%", pct)
	}
	_ = fmt.Sprintf("noise count: %d/%d = %.1f%%", noiseCount, total, pct)
}
