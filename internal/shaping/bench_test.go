package shaping

import (
	"bytes"
	"testing"

	"ghost/internal/framing"
)

func BenchmarkPassthroughPadder(b *testing.B) {
	p := &PassthroughPadder{}
	payload := make([]byte, 1024)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Pad(f)
	}
}

func BenchmarkProfilePadder(b *testing.B) {
	profile := &Profile{
		Name: "bench-lognormal",
		SizeDist: Distribution{
			Type:   "lognormal",
			Params: []float64{6.0, 0.5},
		},
		BurstConf: BurstConfig{
			MinBurstBytes: 1000,
			MaxBurstBytes: 5000,
		},
	}
	p := NewProfilePadder(profile, 42)

	payload := make([]byte, 1024)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Pad(f)
	}
}

// benchDiscardWriter is a framing.FrameWriter that discards all frames.
type benchDiscardWriter struct{}

func (w *benchDiscardWriter) WriteFrame(*framing.Frame) error { return nil }

func BenchmarkTimerWriter_Performance(b *testing.B) {
	payload := make([]byte, 1024)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	tw := &TimerFrameWriter{
		Timer:    &PassthroughTimer{},
		Selector: &PassthroughSelector{},
		Next:     &benchDiscardWriter{},
	}

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := tw.WriteFrame(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTimerWriter_Stealth(b *testing.B) {
	profile := &Profile{
		Name: "bench-stealth",
		SizeDist: Distribution{
			Type:   "lognormal",
			Params: []float64{6.0, 0.5},
		},
		TimingDist: Distribution{
			Type:   "uniform",
			Params: []float64{1, 5}, // 1-5 ms delays
		},
		BurstConf: BurstConfig{
			MinBurstBytes: 1000,
			MaxBurstBytes: 5000,
			MinPauseMs:    10,
			MaxPauseMs:    50,
		},
	}

	sel := &benchFixedSelector{mode: ModeStealth}
	tw := &TimerFrameWriter{
		Timer:    NewProfileTimer(profile, 42),
		Selector: sel,
		Next:     &benchDiscardWriter{},
	}

	payload := make([]byte, 1024)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := tw.WriteFrame(f); err != nil {
			b.Fatal(err)
		}
	}
}

// benchFixedSelector always returns the configured mode.
type benchFixedSelector struct{ mode Mode }

func (s *benchFixedSelector) Select(int64, int) Mode { return s.mode }

func BenchmarkPadderFrameWriter(b *testing.B) {
	payload := make([]byte, 1024)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	var buf bytes.Buffer
	pw := &PadderFrameWriter{
		Padder: &PassthroughPadder{},
		Next:   &framing.EncoderWriter{Enc: framing.NewEncoder(&buf)},
	}

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := pw.WriteFrame(f); err != nil {
			b.Fatal(err)
		}
	}
}
