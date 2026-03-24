package framing

import (
	"bytes"
	"testing"
)

func BenchmarkEncode_DataFrame(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := enc.Encode(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_DataFrame(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	// Encode once to get the wire bytes.
	var tmp bytes.Buffer
	enc := NewEncoder(&tmp)
	if err := enc.Encode(f); err != nil {
		b.Fatal(err)
	}
	wireBytes := tmp.Bytes()

	buf := bytes.NewReader(nil)
	dec := NewDecoder(buf)

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset(wireBytes)
		if _, err := dec.Decode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeDecode_Roundtrip(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := enc.Encode(f); err != nil {
			b.Fatal(err)
		}
		if _, err := dec.Decode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncode_LargeFrame(b *testing.B) {
	payload := make([]byte, MaxPayloadSize) // 16000 bytes — max allowed
	for i := range payload {
		payload[i] = byte(i)
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  payload,
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	b.SetBytes(int64(MaxPayloadSize))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := enc.Encode(f); err != nil {
			b.Fatal(err)
		}
	}
}
