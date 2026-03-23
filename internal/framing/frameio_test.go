package framing

import (
	"bytes"
	"io"
	"testing"
)

// Compile-time interface satisfaction checks.
var _ FrameWriter = (*EncoderWriter)(nil)
var _ FrameReader = (*DecoderReader)(nil)

func TestEncoderWriterSatisfiesFrameWriter(t *testing.T) {
	var fw FrameWriter = &EncoderWriter{Enc: NewEncoder(&bytes.Buffer{})}
	if fw == nil {
		t.Fatal("EncoderWriter should satisfy FrameWriter")
	}
}

func TestDecoderReaderSatisfiesFrameReader(t *testing.T) {
	var fr FrameReader = &DecoderReader{Dec: NewDecoder(&bytes.Buffer{})}
	if fr == nil {
		t.Fatal("DecoderReader should satisfy FrameReader")
	}
}

func TestRoundtripBasic(t *testing.T) {
	var buf bytes.Buffer
	fw := &EncoderWriter{Enc: NewEncoder(&buf)}
	fr := &DecoderReader{Dec: NewDecoder(&buf)}

	orig := &Frame{
		Type:     FrameData,
		StreamID: 42,
		Payload:  []byte("hello ghost"),
	}

	if err := fw.WriteFrame(orig); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	assertFrameEqual(t, orig, got)
}

func TestRoundtripAllFrameTypes(t *testing.T) {
	types := []struct {
		name string
		ft   FrameType
	}{
		{"FrameData", FrameData},
		{"FrameOpen", FrameOpen},
		{"FrameClose", FrameClose},
		{"FramePadding", FramePadding},
		{"FrameKeepAlive", FrameKeepAlive},
		{"FrameUDP", FrameUDP},
	}

	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			fw := &EncoderWriter{Enc: NewEncoder(&buf)}
			fr := &DecoderReader{Dec: NewDecoder(&buf)}

			orig := &Frame{
				Type:     tc.ft,
				StreamID: 100,
				Payload:  []byte("type-test"),
			}

			if err := fw.WriteFrame(orig); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}

			got, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}

			assertFrameEqual(t, orig, got)
		})
	}
}

func TestRoundtripWithPadding(t *testing.T) {
	var buf bytes.Buffer
	fw := &EncoderWriter{Enc: NewEncoder(&buf)}
	fr := &DecoderReader{Dec: NewDecoder(&buf)}

	orig := &Frame{
		Type:     FrameData,
		StreamID: 7,
		Payload:  []byte("padded"),
		Padding:  []byte{0x00, 0x00, 0x00, 0x00, 0x00},
	}

	if err := fw.WriteFrame(orig); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	assertFrameEqual(t, orig, got)
}

func TestPipelineMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	fw := &EncoderWriter{Enc: NewEncoder(&buf)}
	fr := &DecoderReader{Dec: NewDecoder(&buf)}

	frames := []*Frame{
		{Type: FrameOpen, StreamID: 1, Payload: []byte("open-1")},
		{Type: FrameData, StreamID: 1, Payload: []byte("data-1")},
		{Type: FrameData, StreamID: 1, Payload: []byte("data-2"), Padding: []byte{0xAA, 0xBB}},
		{Type: FrameKeepAlive, StreamID: 0, Payload: nil},
		{Type: FrameUDP, StreamID: 2, Payload: []byte("udp-packet")},
		{Type: FrameClose, StreamID: 1, Payload: nil},
	}

	for i, f := range frames {
		if err := fw.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame[%d]: %v", i, err)
		}
	}

	for i, orig := range frames {
		got, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		assertFrameEqual(t, orig, got)
	}
}

func TestDecoderReaderEOFOnEmptyReader(t *testing.T) {
	fr := &DecoderReader{Dec: NewDecoder(&bytes.Buffer{})}

	_, err := fr.ReadFrame()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestEncoderWriterErrorPropagation(t *testing.T) {
	fw := &EncoderWriter{Enc: NewEncoder(brokenWriter{})}

	err := fw.WriteFrame(&Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  []byte("fail"),
	})

	if err == nil {
		t.Fatal("expected error from broken writer, got nil")
	}
}

// assertFrameEqual compares two frames field by field.
func assertFrameEqual(t *testing.T, want, got *Frame) {
	t.Helper()

	if got.Type != want.Type {
		t.Errorf("Type: want %d, got %d", want.Type, got.Type)
	}
	if got.StreamID != want.StreamID {
		t.Errorf("StreamID: want %d, got %d", want.StreamID, got.StreamID)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("Payload: want %q, got %q", want.Payload, got.Payload)
	}
	if !bytes.Equal(got.Padding, want.Padding) {
		t.Errorf("Padding: want %x, got %x", want.Padding, got.Padding)
	}
}
