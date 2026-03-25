package framing

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// roundtrip encodes a frame and decodes it back, returning the decoded frame.
func roundtrip(t *testing.T, f *Frame) *Frame {
	t.Helper()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(f); err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec := NewDecoder(&buf)
	got, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// --- ROUNDTRIP TESTS ---

func TestRoundtrip_DataFrame(t *testing.T) {
	f := &Frame{
		Type:     FrameData,
		StreamID: 42,
		Payload:  []byte("hello world"),
	}
	got := roundtrip(t, f)
	if got.Type != FrameData {
		t.Errorf("Type = %d, want %d", got.Type, FrameData)
	}
	if got.StreamID != 42 {
		t.Errorf("StreamID = %d, want 42", got.StreamID)
	}
	if !bytes.Equal(got.Payload, []byte("hello world")) {
		t.Errorf("Payload = %q, want %q", got.Payload, "hello world")
	}
	if len(got.Padding) != 0 {
		t.Errorf("Padding length = %d, want 0", len(got.Padding))
	}
}

func TestRoundtrip_DataFrameMaxSize(t *testing.T) {
	payload := make([]byte, MaxPayloadSize)
	for i := range payload {
		payload[i] = 0xAA
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  payload,
	}
	got := roundtrip(t, f)
	if len(got.Payload) != MaxPayloadSize {
		t.Fatalf("Payload length = %d, want %d", len(got.Payload), MaxPayloadSize)
	}
	if got.Payload[0] != 0xAA {
		t.Errorf("Payload[0] = 0x%02X, want 0xAA", got.Payload[0])
	}
	if got.Payload[MaxPayloadSize-1] != 0xAA {
		t.Errorf("Payload[last] = 0x%02X, want 0xAA", got.Payload[MaxPayloadSize-1])
	}
}

func TestRoundtrip_OpenFrameTCP_IPv4(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "93.184.216.34", Port: 443}
	payload, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	f := &Frame{Type: FrameOpen, StreamID: 1, Payload: payload}
	got := roundtrip(t, f)
	if got.Type != FrameOpen {
		t.Errorf("Type = %d, want %d", got.Type, FrameOpen)
	}
	decoded, err := DecodeOpenPayload(got.Payload)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Proto != ProtoTCP {
		t.Errorf("Proto = %d, want %d", decoded.Proto, ProtoTCP)
	}
	if decoded.AddrType != AddrIPv4 {
		t.Errorf("AddrType = %d, want %d", decoded.AddrType, AddrIPv4)
	}
	if decoded.Addr != "93.184.216.34" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "93.184.216.34")
	}
	if decoded.Port != 443 {
		t.Errorf("Port = %d, want 443", decoded.Port)
	}
}

func TestRoundtrip_OpenFrameTCP_Domain(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrDomain, Addr: "example.com", Port: 80}
	payload, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	f := &Frame{Type: FrameOpen, StreamID: 1, Payload: payload}
	got := roundtrip(t, f)
	decoded, err := DecodeOpenPayload(got.Payload)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Proto != ProtoTCP {
		t.Errorf("Proto = %d, want %d", decoded.Proto, ProtoTCP)
	}
	if decoded.AddrType != AddrDomain {
		t.Errorf("AddrType = %d, want %d", decoded.AddrType, AddrDomain)
	}
	if decoded.Addr != "example.com" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "example.com")
	}
	if decoded.Port != 80 {
		t.Errorf("Port = %d, want 80", decoded.Port)
	}
}

func TestRoundtrip_OpenFrameUDP_IPv6(t *testing.T) {
	op := &OpenPayload{Proto: ProtoUDP, AddrType: AddrIPv6, Addr: "2001:db8::1", Port: 5353}
	payload, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	f := &Frame{Type: FrameOpen, StreamID: 1, Payload: payload}
	got := roundtrip(t, f)
	decoded, err := DecodeOpenPayload(got.Payload)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Proto != ProtoUDP {
		t.Errorf("Proto = %d, want %d", decoded.Proto, ProtoUDP)
	}
	if decoded.AddrType != AddrIPv6 {
		t.Errorf("AddrType = %d, want %d", decoded.AddrType, AddrIPv6)
	}
	if decoded.Addr != "2001:db8::1" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "2001:db8::1")
	}
	if decoded.Port != 5353 {
		t.Errorf("Port = %d, want 5353", decoded.Port)
	}
}

func TestRoundtrip_CloseFrame(t *testing.T) {
	f := &Frame{Type: FrameClose, StreamID: 7}
	got := roundtrip(t, f)
	if got.Type != FrameClose {
		t.Errorf("Type = %d, want %d", got.Type, FrameClose)
	}
	if got.StreamID != 7 {
		t.Errorf("StreamID = %d, want 7", got.StreamID)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(got.Payload))
	}
}

func TestRoundtrip_PaddingFrame(t *testing.T) {
	f := &Frame{Type: FramePadding, StreamID: 0, Payload: []byte("random noise")}
	got := roundtrip(t, f)
	if got.Type != FramePadding {
		t.Errorf("Type = %d, want %d", got.Type, FramePadding)
	}
	if got.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", got.StreamID)
	}
	if !bytes.Equal(got.Payload, []byte("random noise")) {
		t.Errorf("Payload = %q, want %q", got.Payload, "random noise")
	}
}

func TestRoundtrip_KeepAliveFrame(t *testing.T) {
	f := &Frame{Type: FrameKeepAlive, StreamID: 0}
	got := roundtrip(t, f)
	if got.Type != FrameKeepAlive {
		t.Errorf("Type = %d, want %d", got.Type, FrameKeepAlive)
	}
	if got.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", got.StreamID)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(got.Payload))
	}
}

func TestRoundtrip_UDPFrame(t *testing.T) {
	f := &Frame{Type: FrameUDP, StreamID: 3, Payload: []byte{0x01, 0x02, 0x03, 0x04}}
	got := roundtrip(t, f)
	if got.Type != FrameUDP {
		t.Errorf("Type = %d, want %d", got.Type, FrameUDP)
	}
	if got.StreamID != 3 {
		t.Errorf("StreamID = %d, want 3", got.StreamID)
	}
	if !bytes.Equal(got.Payload, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("Payload = %x, want 01020304", got.Payload)
	}
}

func TestRoundtrip_WithPadding(t *testing.T) {
	padding := make([]byte, 100)
	f := &Frame{
		Type:     FrameData,
		StreamID: 10,
		Payload:  []byte("data"),
		Padding:  padding,
	}
	got := roundtrip(t, f)
	if !bytes.Equal(got.Payload, []byte("data")) {
		t.Errorf("Payload = %q, want %q", got.Payload, "data")
	}
	if len(got.Padding) != 100 {
		t.Errorf("Padding length = %d, want 100", len(got.Padding))
	}
	if !bytes.Equal(got.Padding, padding) {
		t.Errorf("Padding bytes mismatch")
	}
}

func TestRoundtrip_MultipleFrames(t *testing.T) {
	frames := []*Frame{
		{Type: FrameData, StreamID: 1, Payload: []byte("frame0")},
		{Type: FrameOpen, StreamID: 2, Payload: []byte{0x01, 0x01, 10, 0, 0, 1, 0x00, 0x50}},
		{Type: FrameClose, StreamID: 3},
		{Type: FramePadding, StreamID: 0, Payload: []byte("pad")},
		{Type: FrameKeepAlive, StreamID: 0},
		{Type: FrameUDP, StreamID: 5, Payload: []byte{0xFF}},
		{Type: FrameData, StreamID: 6, Payload: []byte("hello")},
		{Type: FrameData, StreamID: 7, Payload: []byte("world"), Padding: make([]byte, 20)},
		{Type: FrameClose, StreamID: 8},
		{Type: FrameData, StreamID: 9, Payload: []byte("last")},
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for i, f := range frames {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("encode frame %d: %v", i, err)
		}
	}

	dec := NewDecoder(&buf)
	for i, want := range frames {
		got, err := dec.Decode()
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("frame %d: Type = %d, want %d", i, got.Type, want.Type)
		}
		if got.StreamID != want.StreamID {
			t.Errorf("frame %d: StreamID = %d, want %d", i, got.StreamID, want.StreamID)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			// nil vs empty slice: both are len 0, compare lengths for nil-payload frames
			if len(got.Payload) != len(want.Payload) {
				t.Errorf("frame %d: Payload length = %d, want %d", i, len(got.Payload), len(want.Payload))
			}
		}
		if len(got.Padding) != len(want.Padding) {
			t.Errorf("frame %d: Padding length = %d, want %d", i, len(got.Padding), len(want.Padding))
		}
	}

	// After all frames, next decode should return io.EOF
	_, err := dec.Decode()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after all frames, got %v", err)
	}
}

// --- ENCODER ERROR TESTS ---

func TestEncode_PayloadTooLarge(t *testing.T) {
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  make([]byte, MaxPayloadSize+1),
	}
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	err := enc.Encode(f)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

// errWriter is a writer that returns an error after n Write calls.
type errWriter struct {
	calls    int
	maxCalls int
}

func (w *errWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.maxCalls {
		return 0, fmt.Errorf("simulated write error")
	}
	return len(p), nil
}

func TestEncode_WriterError(t *testing.T) {
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  []byte("hello"),
	}
	// Allow the header write to succeed, fail on payload write
	w := &errWriter{maxCalls: 1}
	enc := NewEncoder(w)
	err := enc.Encode(f)
	if err == nil {
		t.Fatal("expected error from failing writer, got nil")
	}
}

// --- DECODER ERROR TESTS ---

func TestDecode_EOF(t *testing.T) {
	dec := NewDecoder(bytes.NewReader(nil))
	_, err := dec.Decode()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestDecode_UnexpectedEOF(t *testing.T) {
	// Only 1 byte — partial TotalLen
	dec := NewDecoder(bytes.NewReader([]byte{0x00}))
	_, err := dec.Decode()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestDecode_ZeroTotalLen(t *testing.T) {
	data := []byte{0x00, 0x00}
	dec := NewDecoder(bytes.NewReader(data))
	_, err := dec.Decode()
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestDecode_TotalLenTooSmall(t *testing.T) {
	// TotalLen = 5, less than headerSize (7)
	data := []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}
	dec := NewDecoder(bytes.NewReader(data))
	_, err := dec.Decode()
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestDecode_PayloadLenExceedsTotalLen(t *testing.T) {
	// TotalLen=10: header(7) + 3 bytes for payload+padding
	// But PayloadLen claims 100
	raw := []byte{
		0x00, 0x0A, // TotalLen = 10
		0x00,                   // Type = FrameData
		0x00, 0x00, 0x00, 0x01, // StreamID = 1
		0x00, 0x64, // PayloadLen = 100
		0xAA, 0xBB, 0xCC, // 3 filler bytes
	}
	dec := NewDecoder(bytes.NewReader(raw))
	_, err := dec.Decode()
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestDecode_UnknownFrameType(t *testing.T) {
	// Valid frame with unknown type 0xFF, header-only (no payload)
	raw := []byte{
		0x00, 0x07, // TotalLen = 7
		0xFF,                   // Type = 0xFF (unknown)
		0x00, 0x00, 0x00, 0x00, // StreamID = 0
		0x00, 0x00, // PayloadLen = 0
	}
	dec := NewDecoder(bytes.NewReader(raw))
	got, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Type != 0xFF {
		t.Errorf("Type = 0x%02X, want 0xFF", got.Type)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(got.Payload))
	}
	if got.Padding != nil {
		t.Errorf("Padding = %v, want nil", got.Padding)
	}
}

// --- OPENPAYLOAD TESTS ---

func TestOpenPayload_EncodeDecode_IPv4(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "93.184.216.34", Port: 443}
	data, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	// Proto(1) + AddrType(1) + IPv4(4) + Port(2) = 8
	if len(data) != 8 {
		t.Fatalf("encoded length = %d, want 8", len(data))
	}
	decoded, err := DecodeOpenPayload(data)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Proto != ProtoTCP {
		t.Errorf("Proto = %d, want %d", decoded.Proto, ProtoTCP)
	}
	if decoded.AddrType != AddrIPv4 {
		t.Errorf("AddrType = %d, want %d", decoded.AddrType, AddrIPv4)
	}
	if decoded.Addr != "93.184.216.34" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "93.184.216.34")
	}
	if decoded.Port != 443 {
		t.Errorf("Port = %d, want 443", decoded.Port)
	}
}

func TestOpenPayload_EncodeDecode_Domain(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrDomain, Addr: "example.com", Port: 80}
	data, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	// Proto(1) + AddrType(1) + LenByte(1) + "example.com"(11) + Port(2) = 16
	if len(data) != 16 {
		t.Fatalf("encoded length = %d, want 16", len(data))
	}
	decoded, err := DecodeOpenPayload(data)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Addr != "example.com" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "example.com")
	}
	if decoded.Port != 80 {
		t.Errorf("Port = %d, want 80", decoded.Port)
	}
}

func TestOpenPayload_EncodeDecode_IPv6(t *testing.T) {
	op := &OpenPayload{Proto: ProtoUDP, AddrType: AddrIPv6, Addr: "2001:db8::1", Port: 5353}
	data, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	// Proto(1) + AddrType(1) + IPv6(16) + Port(2) = 20
	if len(data) != 20 {
		t.Fatalf("encoded length = %d, want 20", len(data))
	}
	decoded, err := DecodeOpenPayload(data)
	if err != nil {
		t.Fatalf("DecodeOpenPayload: %v", err)
	}
	if decoded.Addr != "2001:db8::1" {
		t.Errorf("Addr = %q, want %q", decoded.Addr, "2001:db8::1")
	}
	if decoded.Port != 5353 {
		t.Errorf("Port = %d, want 5353", decoded.Port)
	}
}

func TestOpenPayload_InvalidAddrType(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: 0xFF, Addr: "test", Port: 80}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for invalid AddrType, got nil")
	}
}

// --- BINARY GOLDEN TEST ---

func TestDecode_KnownBytes(t *testing.T) {
	// Golden test 1: FrameData, StreamID=1, Payload="Hi"
	// TotalLen = 7 + 2 = 9 = 0x0009
	// Wire: 00 09 00 00 00 00 01 00 02 48 69
	golden1 := []byte{
		0x00, 0x09, // TotalLen = 9
		0x00,                   // Type = FrameData (0x00)
		0x00, 0x00, 0x00, 0x01, // StreamID = 1
		0x00, 0x02, // PayloadLen = 2
		0x48, 0x69, // Payload = "Hi"
	}

	// Golden test 2: FrameOpen, StreamID=3, TCP/IPv4 "1.2.3.4":80
	// OpenPayload: [0x01(TCP), 0x01(IPv4), 1,2,3,4, 0x00,0x50(port 80)] = 8 bytes
	// TotalLen = 7 + 8 = 15 = 0x000F
	// Wire: 00 0F 01 00 00 00 03 00 08 01 01 01 02 03 04 00 50
	golden2 := []byte{
		0x00, 0x0F, // TotalLen = 15
		0x01,                   // Type = FrameOpen (0x01)
		0x00, 0x00, 0x00, 0x03, // StreamID = 3
		0x00, 0x08, // PayloadLen = 8
		0x01,                   // Proto = TCP (0x01)
		0x01,                   // AddrType = IPv4 (0x01)
		0x01, 0x02, 0x03, 0x04, // Addr = 1.2.3.4
		0x00, 0x50, // Port = 80
	}

	// Concatenate both golden frames into one stream
	raw := append(golden1, golden2...)
	dec := NewDecoder(bytes.NewReader(raw))

	// Decode golden 1
	f1, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode golden 1: %v", err)
	}
	if f1.Type != FrameData {
		t.Errorf("golden 1: Type = 0x%02X, want 0x%02X", f1.Type, FrameData)
	}
	if f1.StreamID != 1 {
		t.Errorf("golden 1: StreamID = %d, want 1", f1.StreamID)
	}
	if !bytes.Equal(f1.Payload, []byte("Hi")) {
		t.Errorf("golden 1: Payload = %q, want %q", f1.Payload, "Hi")
	}
	if f1.Padding != nil {
		t.Errorf("golden 1: Padding = %v, want nil", f1.Padding)
	}

	// Decode golden 2
	f2, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode golden 2: %v", err)
	}
	if f2.Type != FrameOpen {
		t.Errorf("golden 2: Type = 0x%02X, want 0x%02X", f2.Type, FrameOpen)
	}
	if f2.StreamID != 3 {
		t.Errorf("golden 2: StreamID = %d, want 3", f2.StreamID)
	}

	// Decode the OpenPayload from golden 2
	op, err := DecodeOpenPayload(f2.Payload)
	if err != nil {
		t.Fatalf("golden 2: DecodeOpenPayload: %v", err)
	}
	if op.Proto != ProtoTCP {
		t.Errorf("golden 2: Proto = %d, want %d", op.Proto, ProtoTCP)
	}
	if op.AddrType != AddrIPv4 {
		t.Errorf("golden 2: AddrType = %d, want %d", op.AddrType, AddrIPv4)
	}
	if op.Addr != "1.2.3.4" {
		t.Errorf("golden 2: Addr = %q, want %q", op.Addr, "1.2.3.4")
	}
	if op.Port != 80 {
		t.Errorf("golden 2: Port = %d, want 80", op.Port)
	}

	// Verify the encoder produces the exact same bytes for golden 1
	var encBuf bytes.Buffer
	enc := NewEncoder(&encBuf)
	if err := enc.Encode(&Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  []byte("Hi"),
	}); err != nil {
		t.Fatalf("encode golden 1: %v", err)
	}
	if !bytes.Equal(encBuf.Bytes(), golden1) {
		t.Errorf("encoded golden 1 = %x, want %x", encBuf.Bytes(), golden1)
	}

	// Verify the encoder produces the exact same bytes for golden 2
	encBuf.Reset()
	opPayload := []byte{0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50}
	if err := enc.Encode(&Frame{
		Type:     FrameOpen,
		StreamID: 3,
		Payload:  opPayload,
	}); err != nil {
		t.Fatalf("encode golden 2: %v", err)
	}
	if !bytes.Equal(encBuf.Bytes(), golden2) {
		t.Errorf("encoded golden 2 = %x, want %x", encBuf.Bytes(), golden2)
	}

	// Also verify EncodeOpenPayload produces the expected payload bytes
	opEncoded, err := EncodeOpenPayload(&OpenPayload{
		Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "1.2.3.4", Port: 80,
	})
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	expectedPayload := []byte{0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50}
	if !bytes.Equal(opEncoded, expectedPayload) {
		t.Errorf("EncodeOpenPayload = %x, want %x", opEncoded, expectedPayload)
	}
}

// --- COVERAGE TESTS ---

func TestCoverage_EncodeOpenPayload_InvalidIPv4(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "not-an-ip", Port: 80}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for invalid IPv4, got nil")
	}
}

func TestCoverage_EncodeOpenPayload_IPv6AsIPv4(t *testing.T) {
	// An IPv6 address provided with AddrIPv4 type — To4() returns nil
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "2001:db8::1", Port: 80}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for IPv6 address with AddrIPv4 type, got nil")
	}
}

func TestCoverage_EncodeOpenPayload_InvalidIPv6(t *testing.T) {
	op := &OpenPayload{Proto: ProtoUDP, AddrType: AddrIPv6, Addr: "not-an-ip", Port: 53}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for invalid IPv6, got nil")
	}
}

func TestCoverage_EncodeOpenPayload_IPv4AsIPv6(t *testing.T) {
	// An IPv4 address provided with AddrIPv6 type — To4() returns non-nil
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv6, Addr: "1.2.3.4", Port: 443}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for IPv4 address with AddrIPv6 type, got nil")
	}
}

func TestCoverage_EncodeOpenPayload_DomainTooLong(t *testing.T) {
	long := string(make([]byte, 256))
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrDomain, Addr: long, Port: 80}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for domain >255 chars, got nil")
	}
}

func TestCoverage_EncodeOpenPayload_EmptyDomain(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrDomain, Addr: "", Port: 80}
	_, err := EncodeOpenPayload(op)
	if err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
}

func TestCoverage_DecodeOpenPayload_TooShort(t *testing.T) {
	// Only 1 byte — less than the minimum 2 (Proto + AddrType)
	_, err := DecodeOpenPayload([]byte{0x01})
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_TruncatedIPv4(t *testing.T) {
	// Proto + AddrType(IPv4) + only 3 bytes (need 4+2=6)
	data := []byte{0x01, 0x01, 10, 0, 0}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_TruncatedIPv6(t *testing.T) {
	// Proto + AddrType(IPv6) + only 10 bytes (need 16+2=18)
	data := make([]byte, 12)
	data[0] = byte(ProtoTCP)
	data[1] = byte(AddrIPv6)
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_TruncatedDomain(t *testing.T) {
	// Proto + AddrType(Domain) + length=10 but only 5 bytes of domain data + no port
	data := []byte{0x01, 0x03, 10, 'a', 'b', 'c', 'd', 'e'}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_MissingDomainLen(t *testing.T) {
	// Proto + AddrType(Domain) + nothing else
	data := []byte{0x01, 0x03}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_ZeroDomainLen(t *testing.T) {
	// Proto + AddrType(Domain) + length=0 — invalid
	data := []byte{0x01, 0x03, 0x00, 0x00, 0x50}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_MissingPort(t *testing.T) {
	// Proto + AddrType(Domain) + length=3 + "abc" but no 2-byte port
	data := []byte{0x01, 0x03, 0x03, 'a', 'b', 'c'}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_DecodeOpenPayload_UnknownAddrType(t *testing.T) {
	// Proto + AddrType=0xFE (unknown)
	data := []byte{0x01, 0xFE, 0x00, 0x00}
	_, err := DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

func TestCoverage_Roundtrip_PaddingOnly(t *testing.T) {
	// Frame with nil Payload and non-nil Padding — tests the payloadLen==0 path
	// with padding write in the encoder
	padding := make([]byte, 50)
	for i := range padding {
		padding[i] = 0xBB
	}
	f := &Frame{
		Type:     FrameData,
		StreamID: 5,
		Payload:  nil,
		Padding:  padding,
	}
	got := roundtrip(t, f)
	if len(got.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(got.Payload))
	}
	if len(got.Padding) != 50 {
		t.Errorf("Padding length = %d, want 50", len(got.Padding))
	}
	if got.Padding[0] != 0xBB || got.Padding[49] != 0xBB {
		t.Errorf("Padding content mismatch")
	}
}

func TestCoverage_Roundtrip_MinimalFrame(t *testing.T) {
	// Frame with no payload and no padding — TotalLen == headerSize (7).
	// FrameKeepAlive is used because it is a connection-level frame that
	// naturally carries StreamID=0 and no payload.
	f := &Frame{
		Type:     FrameKeepAlive,
		StreamID: 0,
	}
	got := roundtrip(t, f)
	if got.Type != FrameKeepAlive {
		t.Errorf("Type = %d, want %d", got.Type, FrameKeepAlive)
	}
	if got.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", got.StreamID)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(got.Payload))
	}
	if got.Padding != nil {
		t.Errorf("Padding = %v, want nil", got.Padding)
	}
}

func TestDecodeOpenPayload_TrailingBytes(t *testing.T) {
	// Encode a valid IPv4 payload, then append trailing garbage.
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "93.184.216.34", Port: 443}
	data, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	data = append(data, 0xFF, 0xFE) // trailing bytes
	_, err = DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt for trailing bytes, got %v", err)
	}
}

func TestDecodeOpenPayload_UnknownProto(t *testing.T) {
	// Valid IPv4 payload but with an unknown proto value.
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "93.184.216.34", Port: 443}
	data, err := EncodeOpenPayload(op)
	if err != nil {
		t.Fatalf("EncodeOpenPayload: %v", err)
	}
	data[0] = 0xFF // unknown proto
	_, err = DecodeOpenPayload(data)
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt for unknown proto, got %v", err)
	}
}

func TestCoverage_Encode_PaddingWriteError(t *testing.T) {
	// Writer that succeeds on header and payload writes but fails on padding
	f := &Frame{
		Type:     FrameData,
		StreamID: 1,
		Payload:  []byte("hi"),
		Padding:  make([]byte, 10),
	}
	w := &errWriter{maxCalls: 2} // allow header + payload, fail on padding
	enc := NewEncoder(w)
	err := enc.Encode(f)
	if err == nil {
		t.Fatal("expected error from padding write, got nil")
	}
}

func TestCoverage_Decode_TruncatedBody(t *testing.T) {
	// TotalLen=10 but only provide 3 body bytes (need 10)
	raw := []byte{
		0x00, 0x0A, // TotalLen = 10
		0x00, 0x00, 0x00, // only 3 of 10 body bytes
	}
	dec := NewDecoder(bytes.NewReader(raw))
	_, err := dec.Decode()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestCoverage_Decode_PayloadLenExceedsMax(t *testing.T) {
	// Construct a frame where PayloadLen > MaxPayloadSize
	// TotalLen must be at least headerSize + PayloadLen, but we can cheat
	// by having TotalLen large enough while PayloadLen = MaxPayloadSize+1
	payloadLen := MaxPayloadSize + 1 // 16001
	totalLen := headerSize + payloadLen
	buf := make([]byte, 2+totalLen)
	buf[0] = byte(totalLen >> 8)
	buf[1] = byte(totalLen)
	buf[2] = 0x00 // Type
	// StreamID = 0 at buf[3:7]
	buf[7] = byte(payloadLen >> 8)
	buf[8] = byte(payloadLen)
	dec := NewDecoder(bytes.NewReader(buf))
	_, err := dec.Decode()
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("expected ErrFrameCorrupt, got %v", err)
	}
}

// --- VALIDATEFRAME TESTS ---

func TestValidateFrame_Valid_Data(t *testing.T) {
	f := &Frame{Type: FrameData, StreamID: 1, Payload: []byte("hello")}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FrameData) = %v, want nil", err)
	}
}

func TestValidateFrame_Valid_Open(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "93.184.216.34", Port: 443}
	payload, _ := EncodeOpenPayload(op)
	f := &Frame{Type: FrameOpen, StreamID: 1, Payload: payload}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FrameOpen) = %v, want nil", err)
	}
}

func TestValidateFrame_Valid_Close(t *testing.T) {
	f := &Frame{Type: FrameClose, StreamID: 7}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FrameClose) = %v, want nil", err)
	}
}

func TestValidateFrame_Valid_Padding(t *testing.T) {
	f := &Frame{Type: FramePadding, StreamID: 0, Payload: []byte("random noise")}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FramePadding) = %v, want nil", err)
	}
}

func TestValidateFrame_Valid_KeepAlive(t *testing.T) {
	f := &Frame{Type: FrameKeepAlive, StreamID: 0}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FrameKeepAlive) = %v, want nil", err)
	}
}

func TestValidateFrame_Valid_UDP(t *testing.T) {
	f := &Frame{Type: FrameUDP, StreamID: 3, Payload: []byte{0x01, 0x02, 0x03}}
	if err := ValidateFrame(f); err != nil {
		t.Errorf("ValidateFrame(valid FrameUDP) = %v, want nil", err)
	}
}

func TestValidateFrame_Nil(t *testing.T) {
	err := ValidateFrame(nil)
	if err == nil {
		t.Fatal("ValidateFrame(nil) = nil, want error")
	}
}

func TestValidateFrame_InvalidType(t *testing.T) {
	f := &Frame{Type: 0xFF, StreamID: 1}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(unknown type) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("ValidateFrame(unknown type) error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestValidateFrame_OversizedPayload(t *testing.T) {
	f := &Frame{Type: FrameData, StreamID: 1, Payload: make([]byte, MaxPayloadSize+1)}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(oversized payload) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("ValidateFrame(oversized payload) error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestValidateFrame_DataStreamIDZero(t *testing.T) {
	f := &Frame{Type: FrameData, StreamID: 0, Payload: []byte("data")}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(FrameData StreamID=0) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestValidateFrame_OpenStreamIDZero(t *testing.T) {
	op := &OpenPayload{Proto: ProtoTCP, AddrType: AddrIPv4, Addr: "1.2.3.4", Port: 80}
	payload, _ := EncodeOpenPayload(op)
	f := &Frame{Type: FrameOpen, StreamID: 0, Payload: payload}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(FrameOpen StreamID=0) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestValidateFrame_CloseStreamIDZero(t *testing.T) {
	f := &Frame{Type: FrameClose, StreamID: 0}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(FrameClose StreamID=0) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestValidateFrame_OpenEmptyPayload(t *testing.T) {
	f := &Frame{Type: FrameOpen, StreamID: 1, Payload: nil}
	err := ValidateFrame(f)
	if err == nil {
		t.Fatal("ValidateFrame(FrameOpen empty payload) = nil, want error")
	}
	if !errors.Is(err, ErrFrameCorrupt) {
		t.Errorf("error should wrap ErrFrameCorrupt, got %v", err)
	}
}

func TestEncode_ValidatesFrame(t *testing.T) {
	// Encoder must propagate ValidateFrame errors.
	cases := []struct {
		name string
		f    *Frame
	}{
		{"nil frame", nil},
		{"unknown type", &Frame{Type: 0xFE, StreamID: 1, Payload: []byte("x")}},
		{"data StreamID=0", &Frame{Type: FrameData, StreamID: 0, Payload: []byte("x")}},
		{"open StreamID=0", &Frame{Type: FrameOpen, StreamID: 0, Payload: []byte{0x01}}},
		{"open empty payload", &Frame{Type: FrameOpen, StreamID: 1}},
		{"close StreamID=0", &Frame{Type: FrameClose, StreamID: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := NewEncoder(&buf)
			err := enc.Encode(tc.f)
			if err == nil {
				t.Fatalf("Encode(%s) = nil, want error", tc.name)
			}
		})
	}
}
