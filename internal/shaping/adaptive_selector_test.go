package shaping

import "testing"

// Compile-time interface satisfaction check.
var _ Selector = (*AdaptiveSelector)(nil)

func TestAdaptiveSelectorSatisfiesSelector(t *testing.T) {
	var s Selector = NewAdaptiveSelector(ModeStealth, false)
	if s == nil {
		t.Fatal("AdaptiveSelector should satisfy Selector")
	}
}

func TestAutoDisabled_DefaultStealth(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, false)

	tests := []struct {
		byteRate    int64
		streamCount int
	}{
		{0, 0},
		{1024, 1},
		{2 * 1024 * 1024, 10},
		{500, 5},
	}
	for _, tc := range tests {
		got := s.Select(tc.byteRate, tc.streamCount)
		if got != ModeStealth {
			t.Errorf("Select(%d, %d) = %d, want ModeStealth(%d)", tc.byteRate, tc.streamCount, got, ModeStealth)
		}
	}
}

func TestAutoDisabled_DefaultPerformance(t *testing.T) {
	s := NewAdaptiveSelector(ModePerformance, false)

	tests := []struct {
		byteRate    int64
		streamCount int
	}{
		{0, 0},
		{1024, 1},
		{2 * 1024 * 1024, 10},
		{500, 5},
	}
	for _, tc := range tests {
		got := s.Select(tc.byteRate, tc.streamCount)
		if got != ModePerformance {
			t.Errorf("Select(%d, %d) = %d, want ModePerformance(%d)", tc.byteRate, tc.streamCount, got, ModePerformance)
		}
	}
}

func TestAutoEnabled_ZeroStreams(t *testing.T) {
	s := NewAdaptiveSelector(ModePerformance, true)
	got := s.Select(2*1024*1024, 0)
	if got != ModeStealth {
		t.Errorf("Select with streamCount=0: got %d, want ModeStealth(%d)", got, ModeStealth)
	}
}

func TestAutoEnabled_HighByteRate(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, true)
	got := s.Select(2*1024*1024, 1) // 2 MB/s
	if got != ModePerformance {
		t.Errorf("Select with high byteRate: got %d, want ModePerformance(%d)", got, ModePerformance)
	}
}

func TestAutoEnabled_LowByteRate(t *testing.T) {
	s := NewAdaptiveSelector(ModePerformance, true)
	got := s.Select(1024, 1) // 1 KB/s
	if got != ModeStealth {
		t.Errorf("Select with low byteRate: got %d, want ModeStealth(%d)", got, ModeStealth)
	}
}

func TestAutoEnabled_MediumByteRate(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, true)
	got := s.Select(100*1024, 1) // 100 KB/s
	if got != ModeBalanced {
		t.Errorf("Select with medium byteRate: got %d, want ModeBalanced(%d)", got, ModeBalanced)
	}
}

func TestBoundary_ExactlyAtBulkThreshold(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, true)
	// byteRate exactly at bulkThreshold (200KB/s) — > is strict, so should be Balanced
	got := s.Select(200*1024, 1)
	if got != ModeBalanced {
		t.Errorf("Select at exact bulkThreshold: got %d, want ModeBalanced(%d)", got, ModeBalanced)
	}
}

func TestBoundary_ExactlyAtIdleThreshold(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, true)
	// byteRate exactly at idleThreshold (10KB/s) — < is strict, so should be Balanced
	got := s.Select(10*1024, 1)
	if got != ModeBalanced {
		t.Errorf("Select at exact idleThreshold: got %d, want ModeBalanced(%d)", got, ModeBalanced)
	}
}

func TestSetThresholds_ChangesBehavior(t *testing.T) {
	s := NewAdaptiveSelector(ModeStealth, true)
	s.SetThresholds(100, 10)

	// byteRate=50 is between idle(10) and bulk(100) → Balanced
	got := s.Select(50, 1)
	if got != ModeBalanced {
		t.Errorf("Select after SetThresholds(100,10) with byteRate=50: got %d, want ModeBalanced(%d)", got, ModeBalanced)
	}

	// byteRate=5 is below idle(10) → Stealth
	got = s.Select(5, 1)
	if got != ModeStealth {
		t.Errorf("Select after SetThresholds(100,10) with byteRate=5: got %d, want ModeStealth(%d)", got, ModeStealth)
	}

	// byteRate=200 is above bulk(100) → Performance
	got = s.Select(200, 1)
	if got != ModePerformance {
		t.Errorf("Select after SetThresholds(100,10) with byteRate=200: got %d, want ModePerformance(%d)", got, ModePerformance)
	}
}
