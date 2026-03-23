package shaping

import (
	"bytes"
	"io"
	"testing"

	"ghost/internal/framing"
)

// Compile-time interface satisfaction checks.
var _ Padder = (*ProfilePadder)(nil)
var _ framing.FrameWriter = (*PadderFrameWriter)(nil)
var _ framing.FrameReader = (*UnpadderFrameReader)(nil)

func lognormalProfile() *Profile {
	return &Profile{
		Name: "test-lognormal",
		SizeDist: Distribution{
			Type:   "lognormal",
			Params: []float64{6.0, 0.5}, // median ~403 bytes
		},
	}
}

func lognormalProfileWithBurst() *Profile {
	return &Profile{
		Name: "test-lognormal-burst",
		SizeDist: Distribution{
			Type:   "lognormal",
			Params: []float64{6.0, 0.5},
		},
		BurstConf: BurstConfig{
			MinBurstBytes: 1000,
			MaxBurstBytes: 5000,
		},
	}
}

func TestProfilePadderSatisfiesPadder(t *testing.T) {
	var p Padder = NewProfilePadder(lognormalProfile(), 1)
	if p == nil {
		t.Fatal("ProfilePadder should satisfy Padder")
	}
}

func TestPadderFrameWriterSatisfiesFrameWriter(t *testing.T) {
	var fw framing.FrameWriter = &PadderFrameWriter{
		Padder: &PassthroughPadder{},
		Next:   &framing.EncoderWriter{Enc: framing.NewEncoder(&bytes.Buffer{})},
	}
	if fw == nil {
		t.Fatal("PadderFrameWriter should satisfy framing.FrameWriter")
	}
}

func TestUnpadderFrameReaderSatisfiesFrameReader(t *testing.T) {
	var fr framing.FrameReader = &UnpadderFrameReader{
		Padder: &PassthroughPadder{},
		Src:    &framing.DecoderReader{Dec: framing.NewDecoder(&bytes.Buffer{})},
	}
	if fr == nil {
		t.Fatal("UnpadderFrameReader should satisfy framing.FrameReader")
	}
}

func TestPad_Lognormal_IncreasesSize(t *testing.T) {
	p := NewProfilePadder(lognormalProfile(), 42)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  []byte("hi"),
	}

	origSize := headerSize + len(f.Payload) + len(f.Padding)
	frames := p.Pad(f)
	if len(frames) == 0 {
		t.Fatal("Pad returned empty slice")
	}

	// The last frame is always the data frame.
	data := frames[len(frames)-1]
	paddedSize := headerSize + len(data.Payload) + len(data.Padding)
	if paddedSize < origSize {
		t.Errorf("padded size %d < original size %d", paddedSize, origSize)
	}
}

func TestPad_NeverShrinksFrames(t *testing.T) {
	// Use uniform [8, 20] so targets are much smaller than frame.
	prof := &Profile{
		Name: "small-target",
		SizeDist: Distribution{
			Type:   "uniform",
			Params: []float64{8, 20},
		},
	}
	p := NewProfilePadder(prof, 99)

	payload := make([]byte, 500)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 1,
		Payload:  payload,
	}
	origPayloadLen := len(f.Payload)

	frames := p.Pad(f)
	data := frames[len(frames)-1]
	if len(data.Payload) != origPayloadLen {
		t.Errorf("Payload length changed: want %d, got %d", origPayloadLen, len(data.Payload))
	}
	// Padding should not be added (target <= current).
	if len(data.Padding) != 0 {
		t.Errorf("expected no padding added, got %d bytes", len(data.Padding))
	}
}

func TestUnpad_StripsDataFramePadding(t *testing.T) {
	p := NewProfilePadder(lognormalProfile(), 1)
	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 5,
		Payload:  []byte("data"),
		Padding:  make([]byte, 100),
	}

	result := p.Unpad(f)
	if result == nil {
		t.Fatal("Unpad should not return nil for data frame")
	}
	if result.Padding != nil {
		t.Errorf("Unpad should strip Padding, got len=%d", len(result.Padding))
	}
	if string(result.Payload) != "data" {
		t.Errorf("Unpad should preserve Payload, got %q", result.Payload)
	}
}

func TestUnpad_ReturnsNilForPaddingFrame(t *testing.T) {
	p := NewProfilePadder(lognormalProfile(), 1)
	f := &framing.Frame{
		Type:     framing.FramePadding,
		StreamID: 0,
		Padding:  make([]byte, 50),
	}

	result := p.Unpad(f)
	if result != nil {
		t.Error("Unpad should return nil for FramePadding")
	}
}

func TestPadderFrameWriter_ForwardsPaddedFrames(t *testing.T) {
	var buf bytes.Buffer
	enc := framing.NewEncoder(&buf)
	next := &framing.EncoderWriter{Enc: enc}

	pw := &PadderFrameWriter{
		Padder: NewProfilePadder(lognormalProfile(), 7),
		Next:   next,
	}

	f := &framing.Frame{
		Type:     framing.FrameData,
		StreamID: 3,
		Payload:  []byte("forward-test"),
	}

	if err := pw.WriteFrame(f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Decode what was written.
	dec := framing.NewDecoder(&buf)
	got, err := dec.Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.Type != framing.FrameData {
		t.Errorf("Type: want %d, got %d", framing.FrameData, got.Type)
	}
	if got.StreamID != 3 {
		t.Errorf("StreamID: want 3, got %d", got.StreamID)
	}
	if string(got.Payload) != "forward-test" {
		t.Errorf("Payload: want %q, got %q", "forward-test", got.Payload)
	}
}

func TestUnpadderFrameReader_SkipsPaddingFrames(t *testing.T) {
	var buf bytes.Buffer
	enc := framing.NewEncoder(&buf)

	// Write: padding, padding, data, padding, data.
	frames := []*framing.Frame{
		{Type: framing.FramePadding, StreamID: 0, Padding: make([]byte, 10)},
		{Type: framing.FramePadding, StreamID: 0, Padding: make([]byte, 20)},
		{Type: framing.FrameData, StreamID: 1, Payload: []byte("first")},
		{Type: framing.FramePadding, StreamID: 0, Padding: make([]byte, 5)},
		{Type: framing.FrameData, StreamID: 2, Payload: []byte("second")},
	}
	for i, f := range frames {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("Encode[%d]: %v", i, err)
		}
	}

	ur := &UnpadderFrameReader{
		Padder: NewProfilePadder(lognormalProfile(), 1),
		Src:    &framing.DecoderReader{Dec: framing.NewDecoder(&buf)},
	}

	// Should get "first" (skipping two padding frames).
	got1, err := ur.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if string(got1.Payload) != "first" {
		t.Errorf("frame 1 Payload: want %q, got %q", "first", got1.Payload)
	}
	if got1.Padding != nil {
		t.Errorf("frame 1 Padding should be nil, got len=%d", len(got1.Padding))
	}

	// Should get "second" (skipping one padding frame).
	got2, err := ur.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if string(got2.Payload) != "second" {
		t.Errorf("frame 2 Payload: want %q, got %q", "second", got2.Payload)
	}

	// Next read should return EOF.
	_, err = ur.ReadFrame()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}

func TestLoadProfile_ValidJSON(t *testing.T) {
	data := []byte(`{
		"name": "chrome-tls",
		"size_distribution": {
			"type": "lognormal",
			"params": [6.0, 0.5]
		},
		"timing_distribution": {
			"type": "uniform",
			"params": [10, 50]
		},
		"burst_config": {
			"min_burst_bytes": 1000,
			"max_burst_bytes": 5000,
			"min_pause_ms": 50,
			"max_pause_ms": 200,
			"burst_count_distribution": {
				"type": "uniform",
				"params": [2, 8]
			}
		}
	}`)

	prof, err := parseProfile(data)
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	if prof.Name != "chrome-tls" {
		t.Errorf("Name: want %q, got %q", "chrome-tls", prof.Name)
	}
	if prof.SizeDist.Type != "lognormal" {
		t.Errorf("SizeDist.Type: want %q, got %q", "lognormal", prof.SizeDist.Type)
	}
	if prof.BurstConf.MinBurstBytes != 1000 {
		t.Errorf("BurstConf.MinBurstBytes: want 1000, got %d", prof.BurstConf.MinBurstBytes)
	}
}

func TestLoadProfile_InvalidJSON(t *testing.T) {
	_, err := parseProfile([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProfile_UnsupportedDistType(t *testing.T) {
	data := []byte(`{
		"name": "bad",
		"size_distribution": {"type": "gaussian", "params": [0, 1]}
	}`)
	_, err := parseProfile(data)
	if err == nil {
		t.Fatal("expected error for unsupported distribution type")
	}
}

func TestLognormalSampling_Range(t *testing.T) {
	p := NewProfilePadder(lognormalProfile(), 123)

	for i := 0; i < 1000; i++ {
		s := p.sampleSize()
		if s <= 0 {
			t.Fatalf("sample %d: got %d <= 0", i, s)
		}
		if s > maxFrameSize {
			t.Fatalf("sample %d: got %d > maxFrameSize(%d)", i, s, maxFrameSize)
		}
	}
}

func TestDeterministicSeeding(t *testing.T) {
	prof := lognormalProfile()

	p1 := NewProfilePadder(prof, 777)
	p2 := NewProfilePadder(prof, 777)

	for i := 0; i < 100; i++ {
		f1 := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  []byte("deterministic"),
		}
		f2 := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  []byte("deterministic"),
		}

		frames1 := p1.Pad(f1)
		frames2 := p2.Pad(f2)

		if len(frames1) != len(frames2) {
			t.Fatalf("iteration %d: frame count mismatch: %d vs %d", i, len(frames1), len(frames2))
		}

		for j := range frames1 {
			size1 := headerSize + len(frames1[j].Payload) + len(frames1[j].Padding)
			size2 := headerSize + len(frames2[j].Payload) + len(frames2[j].Padding)
			if size1 != size2 {
				t.Fatalf("iteration %d, frame %d: size mismatch: %d vs %d", i, j, size1, size2)
			}
		}
	}
}

func TestParetoSampling_Range(t *testing.T) {
	prof := &Profile{
		Name: "pareto-test",
		SizeDist: Distribution{
			Type:   "pareto",
			Params: []float64{100, 1.5},
		},
	}
	p := NewProfilePadder(prof, 42)

	for i := 0; i < 1000; i++ {
		s := p.sampleSize()
		if s < minFrameSize {
			t.Fatalf("sample %d: got %d < minFrameSize(%d)", i, s, minFrameSize)
		}
		if s > maxFrameSize {
			t.Fatalf("sample %d: got %d > maxFrameSize(%d)", i, s, maxFrameSize)
		}
	}
}

func TestUniformSampling_Range(t *testing.T) {
	prof := &Profile{
		Name: "uniform-test",
		SizeDist: Distribution{
			Type:   "uniform",
			Params: []float64{100, 2000},
		},
	}
	p := NewProfilePadder(prof, 42)

	for i := 0; i < 1000; i++ {
		s := p.sampleSize()
		if s < minFrameSize {
			t.Fatalf("sample %d: got %d < minFrameSize(%d)", i, s, minFrameSize)
		}
		if s > maxFrameSize {
			t.Fatalf("sample %d: got %d > maxFrameSize(%d)", i, s, maxFrameSize)
		}
	}
}

func TestEmpiricalSampling_Range(t *testing.T) {
	prof := &Profile{
		Name: "empirical-test",
		SizeDist: Distribution{
			Type:    "empirical",
			Samples: []float64{50, 100, 200, 500, 1000, 2000, 5000},
		},
	}
	p := NewProfilePadder(prof, 42)

	for i := 0; i < 1000; i++ {
		s := p.sampleSize()
		if s < minFrameSize {
			t.Fatalf("sample %d: got %d < minFrameSize(%d)", i, s, minFrameSize)
		}
		if s > maxFrameSize {
			t.Fatalf("sample %d: got %d > maxFrameSize(%d)", i, s, maxFrameSize)
		}
	}
}

func TestPad_NoiseFrameInjection(t *testing.T) {
	prof := lognormalProfileWithBurst()
	// Run many iterations; at least some should produce noise frames.
	noiseCount := 0
	for seed := int64(0); seed < 200; seed++ {
		p := NewProfilePadder(prof, seed)
		f := &framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  []byte("test"),
		}
		frames := p.Pad(f)
		if len(frames) == 2 {
			if frames[0].Type != framing.FramePadding {
				t.Errorf("seed %d: first frame should be FramePadding, got %d", seed, frames[0].Type)
			}
			noiseCount++
		}
	}
	if noiseCount == 0 {
		t.Error("expected at least one noise frame injection across 200 seeds")
	}
}
