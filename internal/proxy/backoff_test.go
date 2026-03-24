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
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
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

	// After reset, should start over at Initial.
	if got := b.Next(); got != 1*time.Second {
		t.Errorf("after reset: got %v, want %v", got, 1*time.Second)
	}
	if got := b.Next(); got != 2*time.Second {
		t.Errorf("second after reset: got %v, want %v", got, 2*time.Second)
	}
}

func TestBackoff_CustomValues(t *testing.T) {
	b := &ExponentialBackoff{
		Initial:    500 * time.Millisecond,
		Max:        5 * time.Second,
		Multiplier: 3.0,
	}

	want := []time.Duration{
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
