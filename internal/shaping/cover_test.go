package shaping

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghost/internal/framing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockFrameWriter records all WriteFrame calls (thread-safe).
type mockFrameWriter struct {
	mu     sync.Mutex
	frames []*framing.Frame
}

func (m *mockFrameWriter) WriteFrame(f *framing.Frame) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Deep-copy payload to avoid data races on shared slices.
	cp := &framing.Frame{
		Type:     f.Type,
		StreamID: f.StreamID,
	}
	if f.Payload != nil {
		cp.Payload = make([]byte, len(f.Payload))
		copy(cp.Payload, f.Payload)
	}
	m.frames = append(m.frames, cp)
	return nil
}

func (m *mockFrameWriter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.frames)
}

func (m *mockFrameWriter) getFrames() []*framing.Frame {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*framing.Frame, len(m.frames))
	copy(out, m.frames)
	return out
}

// mockSelector returns a configurable Mode.
type mockSelector struct {
	mode Mode
}

func (s *mockSelector) Select(byteRate int64, streamCount int) Mode {
	return s.mode
}

// testProfile returns a profile with very short timing values for tests.
func testProfile() *Profile {
	return &Profile{
		Name: "test",
		BurstConf: BurstConfig{
			MinBurstBytes: 100,
			MaxBurstBytes: 1000,
			MinPauseMs:    10,
			MaxPauseMs:    50,
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCoverGenerator_StartsAndStops(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)

	// Verify running state instead of goroutine counts (which are
	// unreliable under coverage instrumentation).
	cg.mu.Lock()
	running := cg.running
	cg.mu.Unlock()
	if !running {
		t.Error("expected running=true after Start")
	}

	cg.Stop()
	time.Sleep(100 * time.Millisecond)

	cg.mu.Lock()
	running = cg.running
	cg.mu.Unlock()
	if running {
		t.Error("expected running=false after Stop")
	}
}

func TestCoverGenerator_InjectsTrafficWhenIdle(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)
	cg.UpdateStats(0, 0) // idle

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)
	defer cg.Stop()

	// The initial interval is 5–15s in production but the run loop
	// uses that for real. We need to wait a bit. However, the initial
	// delay is randomised with the seed. For seed=42, let's just wait
	// a reasonable time. If no frame appears after a timeout, we
	// inject directly to verify the mechanism.
	deadline := time.After(20 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for cover traffic injection")
		default:
			if w.count() > 0 {
				return // success
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestCoverGenerator_SilentWhenActive(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModePerformance}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)
	cg.UpdateStats(1000000, 5) // active: high byte rate, multiple streams

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)
	defer cg.Stop()

	// Wait long enough that at least one timer tick would fire.
	time.Sleep(18 * time.Second)

	if w.count() > 0 {
		t.Errorf("expected no frames when active, got %d", w.count())
	}
}

func TestCoverGenerator_KeepAliveFrameType(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	// Manually inject many times to get at least one keep-alive.
	for i := 0; i < 100; i++ {
		cg.injectIdleTraffic()
	}

	frames := w.getFrames()
	found := false
	for _, f := range frames {
		if f.Type == framing.FrameKeepAlive {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one FrameKeepAlive frame among injections")
	}
}

func TestCoverGenerator_PaddingFrameSize(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 99)

	// Directly call analytics ping many times.
	for i := 0; i < 50; i++ {
		cg.injectAnalyticsPing()
	}

	frames := w.getFrames()
	for _, f := range frames {
		if f.Type != framing.FramePadding {
			t.Errorf("expected FramePadding, got %d", f.Type)
		}
		size := len(f.Payload)
		if size < 100 || size > 500 {
			t.Errorf("analytics ping payload size %d out of range [100, 500]", size)
		}
	}
}

func TestCoverGenerator_MiniBurst(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 77)

	cg.injectMiniBurst()

	count := w.count()
	if count < 2 || count > 5 {
		t.Errorf("mini-burst produced %d frames, expected 2–5", count)
	}

	frames := w.getFrames()
	for _, f := range frames {
		if f.Type != framing.FramePadding {
			t.Errorf("expected FramePadding in burst, got %d", f.Type)
		}
		size := len(f.Payload)
		if size < 50 || size > 200 {
			t.Errorf("burst frame payload size %d out of range [50, 200]", size)
		}
	}
}

func TestCoverGenerator_IntervalRange(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 123)

	patterns := []struct {
		pat pattern
		min time.Duration
		max time.Duration
	}{
		{patternKeepAlive, 30 * time.Second, 60 * time.Second},
		{patternAnalytics, 60 * time.Second, 180 * time.Second},
		{patternMiniBurst, 180 * time.Second, 600 * time.Second},
	}

	for _, tc := range patterns {
		for i := 0; i < 100; i++ {
			cg.mu.Lock()
			cg.lastPattern = tc.pat
			d := cg.nextInterval()
			cg.mu.Unlock()

			if d < tc.min || d > tc.max {
				t.Errorf("pattern %d: interval %v out of range [%v, %v]", tc.pat, d, tc.min, tc.max)
			}
		}
	}
}

func TestCoverGenerator_UpdateStats(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	cg.UpdateStats(500, 3)
	cg.mu.Lock()
	br := cg.byteRate
	sc := cg.streamCount
	cg.mu.Unlock()

	if br != 500 {
		t.Errorf("expected byteRate=500, got %d", br)
	}
	if sc != 3 {
		t.Errorf("expected streamCount=3, got %d", sc)
	}

	// With streamCount>0 and ModePerformance, selector should suppress injection.
	sel.mode = ModePerformance
	cg.UpdateStats(1000000, 10)

	// Inject directly — should be suppressed by run() logic but
	// injectIdleTraffic always injects (it's the run() loop that gates).
	// Instead verify that UpdateStats changed the internal state.
	cg.mu.Lock()
	br2 := cg.byteRate
	sc2 := cg.streamCount
	cg.mu.Unlock()
	if br2 != 1000000 || sc2 != 10 {
		t.Errorf("UpdateStats did not update: byteRate=%d streamCount=%d", br2, sc2)
	}
}

func TestCoverGenerator_ContextCancellation(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)

	ctx, cancel := context.WithCancel(context.Background())

	before := runtime.NumGoroutine()
	cg.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	cancel()
	time.Sleep(200 * time.Millisecond)

	final := runtime.NumGoroutine()
	if final > before+1 {
		t.Errorf("goroutine not cleaned up after ctx cancel: before=%d final=%d", before, final)
	}
}

func TestCoverGenerator_ConcurrentSafety(t *testing.T) {
	w := &mockFrameWriter{}
	sel := &mockSelector{mode: ModeStealth}
	prof := testProfile()

	cg := NewCoverGenerator(w, sel, prof, 42)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cg.Start(ctx)
	defer cg.Stop()

	var wg sync.WaitGroup
	var ops atomic.Int64

	// Concurrently call UpdateStats.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cg.UpdateStats(int64(id*100+j), id)
				ops.Add(1)
			}
		}(i)
	}

	// Concurrently inject traffic.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				cg.injectIdleTraffic()
				ops.Add(1)
			}
		}()
	}

	wg.Wait()

	if ops.Load() == 0 {
		t.Fatal("expected concurrent operations to complete")
	}
}
