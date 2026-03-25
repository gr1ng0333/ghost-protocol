package proxy

import (
	"testing"
	"time"
)

func TestBackoff_Exponential(t *testing.T) {
	b := &ExponentialBackoff{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	}

	want := []time.Duration{
		0,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
	}

	for i, w := range want {
		got := b.Next()
		if got != w {
			t.Errorf("attempt %d: got %v, want %v", i, got, w)
		}
	}
}

func TestBackoff_Reset(t *testing.T) {
	b := &ExponentialBackoff{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	}

	// Advance several times.
	for i := 0; i < 4; i++ {
		b.Next()
	}

	b.Reset()

	// After reset, first Next returns 0 (immediate retry).
	if got := b.Next(); got != 0 {
		t.Errorf("after reset: got %v, want 0", got)
	}
	if got := b.Next(); got != 1*time.Second {
		t.Errorf("second after reset: got %v, want %v", got, 1*time.Second)
	}
}

func TestBackoff_CustomValues(t *testing.T) {
	b := &ExponentialBackoff{
		Initial:    500 * time.Millisecond,
		Max:        5 * time.Second,
		Multiplier: 3.0,
	}

	want := []time.Duration{
		0,
		500 * time.Millisecond,
		1500 * time.Millisecond,
		4500 * time.Millisecond,
		5 * time.Second,
	}

	for i, w := range want {
		got := b.Next()
		if got != w {
			t.Errorf("attempt %d: got %v, want %v", i, got, w)
		}
	}
}

func TestBackoff_FirstNextAfterResetIsZero(t *testing.T) {
	b := &ExponentialBackoff{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	}

	// First call ever must be 0.
	if got := b.Next(); got != 0 {
		t.Errorf("first Next: got %v, want 0", got)
	}

	// Advance a few times.
	b.Next()
	b.Next()

	// Reset and verify first call is 0 again.
	b.Reset()
	if got := b.Next(); got != 0 {
		t.Errorf("first Next after Reset: got %v, want 0", got)
	}

	// Second call after reset must be Initial.
	if got := b.Next(); got != 1*time.Second {
		t.Errorf("second Next after Reset: got %v, want %v", got, 1*time.Second)
	}
}
