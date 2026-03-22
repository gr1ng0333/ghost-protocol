package shaping

import (
	"testing"
	"time"

	"ghost/internal/framing"
)

// Compile-time interface satisfaction checks.
var (
	_ Padder   = (*PassthroughPadder)(nil)
	_ Timer    = (*PassthroughTimer)(nil)
	_ Selector = (*PassthroughSelector)(nil)
)

func TestPassthroughPadder_Pad(t *testing.T) {
	p := &PassthroughPadder{}
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 7,
		Payload:  []byte("hello"),
	}

	result := p.Pad(f)
	if len(result) != 1 {
		t.Fatalf("got %d frames, want 1", len(result))
	}
	if result[0] != f {
		t.Fatal("Pad returned a different frame pointer, want same frame")
	}
}

func TestPassthroughPadder_Unpad_DataFrame(t *testing.T) {
	p := &PassthroughPadder{}
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 3,
		Payload:  []byte("data"),
	}

	result := p.Unpad(f)
	if result != f {
		t.Fatal("Unpad returned a different frame pointer, want same frame")
	}
}

func TestPassthroughPadder_Unpad_PaddingFrame(t *testing.T) {
	p := &PassthroughPadder{}
	f := &framing.Frame{
		Type:     framing.FramePadding,
		StreamID: 0,
		Payload:  []byte{0, 0, 0, 0},
	}

	result := p.Unpad(f)
	if result != nil {
		t.Fatalf("Unpad returned %+v for padding frame, want nil", result)
	}
}

func TestPassthroughTimer_Delay(t *testing.T) {
	tm := &PassthroughTimer{}
	d := tm.Delay(1024, 5)
	if d != 0 {
		t.Fatalf("Delay = %v, want 0", d)
	}
}

func TestPassthroughTimer_BurstComplete(t *testing.T) {
	tm := &PassthroughTimer{}
	if tm.BurstComplete(999999, 100) {
		t.Fatal("BurstComplete = true, want false")
	}
}

func TestPassthroughTimer_IdleDuration(t *testing.T) {
	tm := &PassthroughTimer{}
	d := tm.IdleDuration()
	if d != time.Duration(0) {
		t.Fatalf("IdleDuration = %v, want 0", d)
	}
}

func TestPassthroughSelector_Select(t *testing.T) {
	s := &PassthroughSelector{}

	cases := []struct {
		byteRate    int64
		streamCount int
	}{
		{0, 0},
		{1000, 1},
		{1_000_000, 50},
	}

	for _, tc := range cases {
		mode := s.Select(tc.byteRate, tc.streamCount)
		if mode != ModePerformance {
			t.Errorf("Select(%d, %d) = %d, want ModePerformance (%d)",
				tc.byteRate, tc.streamCount, mode, ModePerformance)
		}
	}
}
