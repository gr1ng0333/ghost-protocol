package mux

import (
	"io"
	"sync"
	"testing"

	"ghost/internal/framing"
)

// TestStream_ReadWrite writes data via pushData and reads it back via Read.
func TestStream_ReadWrite(t *testing.T) {
	s := newStream(1, nil, func() {})

	data := []byte("hello, ghost")
	s.pushData(data)

	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello, ghost" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hello, ghost")
	}
}

// TestStream_ReadMultipleChunks pushes 3 chunks and reads all sequentially.
func TestStream_ReadMultipleChunks(t *testing.T) {
	s := newStream(2, nil, func() {})

	chunks := []string{"alpha", "bravo", "charlie"}
	for _, c := range chunks {
		s.pushData([]byte(c))
	}

	for _, want := range chunks {
		buf := make([]byte, 64)
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error reading chunk %q: %v", want, err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("got %q, want %q", string(buf[:n]), want)
		}
	}
}

// TestStream_ReadPartial pushes a large chunk and reads with a small buffer,
// verifying leftover handling.
func TestStream_ReadPartial(t *testing.T) {
	s := newStream(3, nil, func() {})

	data := []byte("abcdefghijklmnop") // 16 bytes
	s.pushData(data)

	// Read first 5 bytes.
	buf := make([]byte, 5)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 || string(buf[:n]) != "abcde" {
		t.Fatalf("first read: got %d bytes %q, want 5 bytes %q", n, string(buf[:n]), "abcde")
	}

	// Read next 5 bytes (from leftover).
	n, err = s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 || string(buf[:n]) != "fghij" {
		t.Fatalf("second read: got %d bytes %q, want 5 bytes %q", n, string(buf[:n]), "fghij")
	}

	// Read remaining 6 bytes.
	buf2 := make([]byte, 10)
	n, err = s.Read(buf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 6 || string(buf2[:n]) != "klmnop" {
		t.Fatalf("third read: got %d bytes %q, want 6 bytes %q", n, string(buf2[:n]), "klmnop")
	}
}

// TestStream_WriteChunking writes a payload larger than MaxPayloadSize,
// verifying writeFn is called multiple times with chunks ≤ MaxPayloadSize.
func TestStream_WriteChunking(t *testing.T) {
	var mu sync.Mutex
	var chunks [][]byte

	writeFn := func(data []byte) error {
		cp := make([]byte, len(data))
		copy(cp, data)
		mu.Lock()
		chunks = append(chunks, cp)
		mu.Unlock()
		return nil
	}

	s := newStream(4, writeFn, func() {})

	// Write 2.5x MaxPayloadSize bytes.
	size := framing.MaxPayloadSize*2 + framing.MaxPayloadSize/2
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := s.Write(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != size {
		t.Fatalf("wrote %d bytes, want %d", n, size)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if len(chunks[0]) != framing.MaxPayloadSize {
		t.Fatalf("chunk 0 size = %d, want %d", len(chunks[0]), framing.MaxPayloadSize)
	}
	if len(chunks[1]) != framing.MaxPayloadSize {
		t.Fatalf("chunk 1 size = %d, want %d", len(chunks[1]), framing.MaxPayloadSize)
	}
	if len(chunks[2]) != framing.MaxPayloadSize/2 {
		t.Fatalf("chunk 2 size = %d, want %d", len(chunks[2]), framing.MaxPayloadSize/2)
	}

	// Verify data integrity by reconstructing.
	var reconstructed []byte
	for _, c := range chunks {
		reconstructed = append(reconstructed, c...)
	}
	for i := range payload {
		if reconstructed[i] != payload[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, reconstructed[i], payload[i])
		}
	}
}

// TestStream_WriteAfterClose verifies Write on a closed stream returns ErrStreamClosed.
func TestStream_WriteAfterClose(t *testing.T) {
	closeCalled := false
	s := newStream(5, func(data []byte) error {
		return nil
	}, func() {
		closeCalled = true
	})

	if err := s.Close(); err != nil {
		t.Fatalf("unexpected error on Close: %v", err)
	}
	if !closeCalled {
		t.Fatal("closeFn was not called")
	}

	_, err := s.Write([]byte("data"))
	if err != ErrStreamClosed {
		t.Fatalf("got error %v, want ErrStreamClosed", err)
	}
}

// TestStream_ReadAfterRemoteClose pushes data, then calls closeRead(),
// and verifies Read returns the data then io.EOF.
func TestStream_ReadAfterRemoteClose(t *testing.T) {
	s := newStream(6, nil, func() {})

	s.pushData([]byte("before-close"))
	s.closeRead()

	// Should still be able to read buffered data.
	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "before-close" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "before-close")
	}

	// Next read should return EOF.
	_, err = s.Read(buf)
	if err != io.EOF {
		t.Fatalf("got error %v, want io.EOF", err)
	}
}

// TestStream_CloseIdempotent verifies Close() called twice doesn't panic.
func TestStream_CloseIdempotent(t *testing.T) {
	callCount := 0
	s := newStream(7, nil, func() {
		callCount++
	})

	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if callCount != 1 {
		t.Fatalf("closeFn called %d times, want 1", callCount)
	}
}

// TestStream_ID verifies ID() returns the correct stream ID.
func TestStream_ID(t *testing.T) {
	s := newStream(42, nil, func() {})
	if s.ID() != 42 {
		t.Fatalf("got ID %d, want 42", s.ID())
	}
}
