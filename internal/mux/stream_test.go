package mux

import (
	"io"
	"sync"
	"testing"

	"ghost/internal/framing"
)

// TestStream_ReadWrite writes data via pushData and reads it back via Read.
func TestStream_ReadWrite(t *testing.T) {
	s := newStream(1, nil, func() {}, nil)

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
	s := newStream(2, nil, func() {}, nil)

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
	s := newStream(3, nil, func() {}, nil)

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

	s := newStream(4, writeFn, func() {}, nil)

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
	}, nil)

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
	s := newStream(6, nil, func() {}, nil)

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
	}, nil)

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
	s := newStream(42, nil, func() {}, nil)
	if s.ID() != 42 {
		t.Fatalf("got ID %d, want 42", s.ID())
	}
}

// TestStream_CloseWrite verifies that after CloseWrite, Write returns
// ErrStreamClosed but Read still works for already-buffered data.
func TestStream_CloseWrite(t *testing.T) {
	closeWriteCalled := false
	closeWriteFn := func() error {
		closeWriteCalled = true
		return nil
	}

	s := newStream(10, func(data []byte) error {
		return nil
	}, func() {}, closeWriteFn)

	// Push data before CloseWrite so readBuf has something.
	s.pushData([]byte("still readable"))

	if err := s.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !closeWriteCalled {
		t.Fatal("closeWriteFn was not called")
	}

	// Write must fail after CloseWrite.
	_, err := s.Write([]byte("should fail"))
	if err != ErrStreamClosed {
		t.Fatalf("Write after CloseWrite: got %v, want ErrStreamClosed", err)
	}

	// Read must still work for buffered data.
	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("Read after CloseWrite: unexpected error: %v", err)
	}
	if string(buf[:n]) != "still readable" {
		t.Fatalf("Read after CloseWrite: got %q, want %q", string(buf[:n]), "still readable")
	}

	// pushData still works (read direction is open).
	s.pushData([]byte("post-closewrite"))
	n, err = s.Read(buf)
	if err != nil {
		t.Fatalf("Read after pushData post-CloseWrite: %v", err)
	}
	if string(buf[:n]) != "post-closewrite" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "post-closewrite")
	}
}

// TestStream_CloseWrite_Idempotent verifies calling CloseWrite twice
// doesn't panic and the callback is invoked only once.
func TestStream_CloseWrite_Idempotent(t *testing.T) {
	callCount := 0
	closeWriteFn := func() error {
		callCount++
		return nil
	}

	s := newStream(11, nil, func() {}, closeWriteFn)

	if err := s.CloseWrite(); err != nil {
		t.Fatalf("first CloseWrite: %v", err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite: %v", err)
	}

	if callCount != 1 {
		t.Fatalf("closeWriteFn called %d times, want 1", callCount)
	}
}

// TestStream_CloseWrite_ThenClose verifies CloseWrite followed by Close
// works correctly: both complete without panic, closeFn is called by Close.
func TestStream_CloseWrite_ThenClose(t *testing.T) {
	closeFnCalled := false
	closeWriteFnCalled := false

	s := newStream(12, func(data []byte) error {
		return nil
	}, func() {
		closeFnCalled = true
	}, func() error {
		closeWriteFnCalled = true
		return nil
	})

	s.pushData([]byte("data"))

	// CloseWrite first.
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !closeWriteFnCalled {
		t.Fatal("closeWriteFn was not called")
	}

	// Write must fail.
	_, err := s.Write([]byte("nope"))
	if err != ErrStreamClosed {
		t.Fatalf("Write after CloseWrite: got %v, want ErrStreamClosed", err)
	}

	// Read buffered data still works.
	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "data" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "data")
	}

	// Full close.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closeFnCalled {
		t.Fatal("closeFn was not called after Close")
	}

	// Read returns EOF after full close.
	_, err = s.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read after Close: got %v, want io.EOF", err)
	}
}
