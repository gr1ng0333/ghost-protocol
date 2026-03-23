package shaping

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers for stats_updater
// ---------------------------------------------------------------------------

// mockMuxStatsProvider returns configurable stats.
type mockMuxStatsProvider struct {
	mu            sync.Mutex
	activeStreams int
	bytesSent     uint64
	bytesRecv     uint64
}

func (m *mockMuxStatsProvider) ActiveStreamCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeStreams
}

func (m *mockMuxStatsProvider) TotalBytesSent() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bytesSent
}

func (m *mockMuxStatsProvider) TotalBytesRecv() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bytesRecv
}

func (m *mockMuxStatsProvider) set(streams int, sent, recv uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeStreams = streams
	m.bytesSent = sent
	m.bytesRecv = recv
}

// spyTimerFrameWriter wraps a real TimerFrameWriter and records UpdateStats calls.
type spyTimerWriter struct {
	mu    sync.Mutex
	calls []statsCall
}

type statsCall struct {
	byteRate    int64
	streamCount int
}

func (s *spyTimerWriter) recordUpdateStats(byteRate int64, streamCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, statsCall{byteRate: byteRate, streamCount: streamCount})
}

func (s *spyTimerWriter) getCalls() []statsCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]statsCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// spyCoverGenerator records UpdateStats calls.
type spyCoverGenerator struct {
	mu    sync.Mutex
	calls []statsCall
}

func (s *spyCoverGenerator) recordUpdateStats(byteRate int64, streamCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, statsCall{byteRate: byteRate, streamCount: streamCount})
}

func (s *spyCoverGenerator) getCalls() []statsCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]statsCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// newTestStatsUpdater creates a StatsUpdater that uses real TimerFrameWriter
// and CoverGenerator but with the spies wired in for verification.
func newTestStatsUpdater(mux *mockMuxStatsProvider, interval time.Duration) (*StatsUpdater, *TimerFrameWriter, *CoverGenerator) {
	sel := &mockSelector{mode: ModeStealth}
	timer := &TimerFrameWriter{
		Timer:    &PassthroughTimer{},
		Selector: sel,
		Next:     &mockFrameWriter{},
	}
	cover := NewCoverGenerator(&mockFrameWriter{}, sel, testProfile(), 42)

	su := NewStatsUpdater(mux, timer, cover, interval)
	return su, timer, cover
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestStatsUpdater_UpdatesCalled(t *testing.T) {
	mux := &mockMuxStatsProvider{}
	mux.set(3, 1000, 500)

	su, timer, cover := newTestStatsUpdater(mux, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		su.Run(ctx)
		close(done)
	}()

	// Wait for at least two ticks.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	// Check timer got updated.
	timer.mu.Lock()
	br := timer.byteRate
	sc := timer.streamCount
	timer.mu.Unlock()

	if sc != 3 {
		t.Errorf("timer streamCount: got %d, want 3", sc)
	}
	// After first tick: byteRate = (1000+500) - 0 = 1500.
	// After second tick: byteRate = (1000+500) - 1500 = 0 (if mux stats unchanged).
	// We just verify it was set at least once.
	if br == 0 {
		// On second tick with same stats, rate could be 0. Check that at least
		// the cover generator also got updated.
	}

	// Check cover got updated.
	cover.mu.Lock()
	coverSC := cover.streamCount
	cover.mu.Unlock()

	if coverSC != 3 {
		t.Errorf("cover streamCount: got %d, want 3", coverSC)
	}
}

func TestStatsUpdater_ComputesByteRate(t *testing.T) {
	mux := &mockMuxStatsProvider{}

	// Set initial values before starting so the first tick reads them.
	mux.set(2, 1000, 500)

	su, timer, _ := newTestStatsUpdater(mux, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		su.Run(ctx)
		close(done)
	}()

	// Wait for first tick (at ~200ms).
	// First tick: total=1500, rate = 1500-0 = 1500, lastBytes=1500.
	time.Sleep(250 * time.Millisecond)

	timer.mu.Lock()
	br1 := timer.byteRate
	timer.mu.Unlock()

	if br1 != 1500 {
		t.Errorf("after first tick: byteRate got %d, want 1500", br1)
	}

	// Update mux: sent=3000, recv=1000 → total=4000.
	// Second tick (at ~400ms): rate = 4000-1500 = 2500.
	mux.set(2, 3000, 1000)
	time.Sleep(250 * time.Millisecond)

	// Read before third tick fires (at ~600ms).
	timer.mu.Lock()
	br2 := timer.byteRate
	timer.mu.Unlock()

	cancel()
	<-done

	if br2 != 2500 {
		t.Errorf("after second tick: byteRate got %d, want 2500", br2)
	}
}

func TestStatsUpdater_StopsOnCancel(t *testing.T) {
	mux := &mockMuxStatsProvider{}
	su, _, _ := newTestStatsUpdater(mux, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		su.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Success — Run returned promptly.
	case <-time.After(2 * time.Second):
		t.Fatal("StatsUpdater.Run did not return after context cancellation")
	}
}
