package mux

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

func TestBufferedPipe_BasicReadWrite(t *testing.T) {
	p := NewBufferedPipe(4096)
	want := []byte("hello, buffered pipe!")
	if _, err := p.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(want))
	n, err := io.ReadFull(p, got)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != len(want) {
		t.Fatalf("Read n = %d, want %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBufferedPipe_WriterDoesNotBlockUntilFull(t *testing.T) {
	p := NewBufferedPipe(4096)
	data := make([]byte, 2048)
	done := make(chan struct{})
	go func() {
		p.Write(data)
		close(done)
	}()
	select {
	case <-done:
		// ok — write returned without blocking
	case <-time.After(1 * time.Second):
		t.Fatal("Write blocked even though buffer has space")
	}
}

func TestBufferedPipe_WriterBlocksWhenFull(t *testing.T) {
	p := NewBufferedPipe(1024)
	// Fill the buffer.
	if _, err := p.Write(make([]byte, 1024)); err != nil {
		t.Fatalf("initial Write: %v", err)
	}

	blocked := make(chan struct{})
	go func() {
		p.Write(make([]byte, 1)) // should block
		close(blocked)
	}()

	select {
	case <-blocked:
		t.Fatal("Write did not block when buffer is full")
	case <-time.After(50 * time.Millisecond):
		// expected — writer is blocked
	}

	// Read to unblock.
	buf := make([]byte, 512)
	p.Read(buf)

	select {
	case <-blocked:
		// ok — writer unblocked after read
	case <-time.After(1 * time.Second):
		t.Fatal("Write still blocked after Read freed space")
	}
}

func TestBufferedPipe_ReaderBlocksWhenEmpty(t *testing.T) {
	p := NewBufferedPipe(4096)
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := p.Read(buf)
		readDone <- buf[:n]
	}()

	select {
	case <-readDone:
		t.Fatal("Read returned on empty pipe without blocking")
	case <-time.After(50 * time.Millisecond):
		// expected — reader is blocked
	}

	want := []byte("unblock")
	p.Write(want)

	select {
	case got := <-readDone:
		if !bytes.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Read still blocked after Write")
	}
}

func TestBufferedPipe_CloseAndDrain(t *testing.T) {
	p := NewBufferedPipe(4096)
	want := []byte("drain me")
	p.Write(want)
	p.Close()

	got := make([]byte, len(want))
	n, err := io.ReadFull(p, got)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("got %q, want %q", got[:n], want)
	}

	// Next read should return EOF.
	_, err = p.Read(got)
	if err != io.EOF {
		t.Fatalf("expected io.EOF after drain, got %v", err)
	}
}

func TestBufferedPipe_ConcurrentReadWrite(t *testing.T) {
	p := NewBufferedPipe(4096)
	const writers = 10
	const perWriter = 1000
	payload := []byte("x")

	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if _, err := p.Write(payload); err != nil {
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		p.Close()
	}()

	totalRead := 0
	buf := make([]byte, 256)
	for {
		n, err := p.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
	}

	expected := writers * perWriter
	if totalRead != expected {
		t.Fatalf("totalRead = %d, want %d", totalRead, expected)
	}
}

func TestBufferedPipe_LargeTransfer(t *testing.T) {
	const pipeSize = 2 << 20   // 2MB
	const totalData = 10 << 20 // 10MB
	p := NewBufferedPipe(pipeSize)

	// Generate deterministic test data.
	src := make([]byte, totalData)
	for i := range src {
		src[i] = byte(i % 251)
	}

	go func() {
		chunkSize := 32 * 1024
		for off := 0; off < len(src); off += chunkSize {
			end := off + chunkSize
			if end > len(src) {
				end = len(src)
			}
			if _, err := p.Write(src[off:end]); err != nil {
				return
			}
		}
		p.Close()
	}()

	dst := make([]byte, 0, totalData)
	buf := make([]byte, 32*1024)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			dst = append(dst, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	if len(dst) != totalData {
		t.Fatalf("received %d bytes, want %d", len(dst), totalData)
	}
	if !bytes.Equal(src, dst) {
		t.Fatal("data mismatch")
	}
}
