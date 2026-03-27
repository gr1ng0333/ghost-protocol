package mux

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"ghost/internal/framing"
)

// --- Edge-case tests for mux streams ---

func TestMux_ZeroLengthPayload(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	type acceptRes struct {
		stream Stream
		dest   Destination
		err    error
	}
	aCh := make(chan acceptRes, 1)
	go func() {
		s, d, err := server.Accept(ctx)
		aCh <- acceptRes{s, d, err}
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cs.Close()

	ar := <-aCh
	if ar.err != nil {
		t.Fatalf("Accept: %v", ar.err)
	}
	ss := ar.stream
	defer ss.Close()

	// Write zero-length payload.
	n, err := cs.Write([]byte{})
	if err != nil {
		t.Fatalf("Write empty: %v", err)
	}
	if n != 0 {
		t.Fatalf("Write returned %d, want 0", n)
	}

	// Write actual data after zero-length to verify stream still works.
	if _, err := cs.Write([]byte("ok")); err != nil {
		t.Fatalf("Write after empty: %v", err)
	}

	buf := make([]byte, 64)
	nr, err := ss.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:nr]) != "ok" {
		t.Fatalf("got %q, want %q", string(buf[:nr]), "ok")
	}
}

func TestMux_MaxLengthPayload(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		aCh <- s
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cs.Close()

	ss := <-aCh
	defer ss.Close()

	// MaxPayloadSize from framing package is 16000.
	payload := make([]byte, framing.MaxPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	// Write in a goroutine since pipes are synchronous.
	go func() {
		if _, err := cs.Write(payload); err != nil {
			t.Errorf("Write max payload: %v", err)
		}
	}()

	got := make([]byte, 0, framing.MaxPayloadSize)
	buf := make([]byte, 32*1024)
	for len(got) < framing.MaxPayloadSize {
		n, err := ss.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (got %d/%d bytes)", err, len(got), framing.MaxPayloadSize)
		}
		got = append(got, buf[:n]...)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: len got=%d want=%d", len(got), len(payload))
	}
}

func TestMux_OpenAfterClose(t *testing.T) {
	t.Parallel()
	client, _ := setupMuxPair(t)

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Open(ctx, "127.0.0.1", 80)
	if err == nil {
		t.Fatal("Open after Close should return error")
	}
}

func TestMux_WriteToClosedStream(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	go func() {
		s, _, err := server.Accept(ctx)
		if err == nil {
			s.Close()
		}
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	cs.Close()

	_, err = cs.Write([]byte("after close"))
	if err == nil {
		t.Fatal("Write to closed stream should return error")
	}
}

func TestMux_ReadFromHalfClosedStream(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		aCh <- s
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cs.Close()

	ss := <-aCh
	defer ss.Close()

	// Client writes data then half-closes.
	if _, err := cs.Write([]byte("half-close data")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Half-close: client signals end of write.
	if cw, ok := cs.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Skip("stream does not support CloseWrite")
	}

	// Server reads buffered data.
	buf := make([]byte, 64)
	n, err := ss.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "half-close data" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "half-close data")
	}

	// Next read should get EOF (remote half-closed).
	_, err = ss.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected io.EOF after half-close, got %v", err)
	}

	// Server should still be able to write back.
	go func() {
		ss.Write([]byte("reply"))
	}()

	n, err = cs.Read(buf)
	if err != nil {
		t.Fatalf("client Read after half-close: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "reply")
	}
}

func TestMux_ConcurrentOpenClose(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	const n = 50
	var wg sync.WaitGroup

	// Server: accept and echo on each stream.
	go func() {
		for {
			s, _, err := server.Accept(ctx)
			if err != nil {
				return
			}
			go func(s Stream) {
				defer s.Close()
				io.Copy(s, s)
			}(s)
		}
	}()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, err := client.Open(ctx, "127.0.0.1", uint16(8000+idx))
			if err != nil {
				return // mux may be closing
			}
			defer s.Close()

			payload := make([]byte, 100)
			for j := range payload {
				payload[j] = byte(idx)
			}
			if _, err := s.Write(payload); err != nil {
				return
			}

			buf := make([]byte, 100)
			total := 0
			for total < 100 {
				nr, err := s.Read(buf[total:])
				if err != nil {
					return
				}
				total += nr
			}
		}(i)
	}

	wg.Wait()
}

func TestMux_DoubleClose(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	go func() {
		s, _, err := server.Accept(ctx)
		if err == nil {
			s.Close()
		}
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// First close should succeed.
	if err := cs.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second close should not panic. Error is acceptable.
	cs.Close()
}

func TestMux_ManyStreams(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	// Server: accept all streams and close them after reading.
	go func() {
		for {
			s, _, err := server.Accept(ctx)
			if err != nil {
				return
			}
			go func(s Stream) {
				defer s.Close()
				io.Copy(io.Discard, s)
			}(s)
		}
	}()

	const total = 200
	for i := 0; i < total; i++ {
		s, err := client.Open(ctx, "127.0.0.1", uint16(7000+(i%1000)))
		if err != nil {
			t.Fatalf("Open stream %d: %v", i, err)
		}
		if _, err := s.Write([]byte("ping")); err != nil {
			t.Fatalf("Write stream %d: %v", i, err)
		}
		s.Close()
	}

	stats := client.Stats()
	if stats.TotalOpened < total {
		t.Errorf("TotalOpened = %d, want >= %d", stats.TotalOpened, total)
	}
}

func TestMux_AcceptAfterClose(t *testing.T) {
	t.Parallel()
	_, server := setupMuxPair(t)

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := server.Accept(ctx)
	if err == nil {
		t.Fatal("Accept after Close should return error")
	}
}

func TestMux_DoubleCloseMux(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)

	// First close.
	if err := client.Close(); err != nil {
		t.Fatalf("first client Close: %v", err)
	}
	// Second close should not panic.
	client.Close()

	if err := server.Close(); err != nil {
		t.Fatalf("first server Close: %v", err)
	}
	server.Close()
}

func TestMux_OpenIPv6Address(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Destination, 1)
	go func() {
		s, d, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer s.Close()
		aCh <- d
	}()

	cs, err := client.Open(ctx, "::1", 443)
	if err != nil {
		t.Fatalf("Open IPv6: %v", err)
	}
	defer cs.Close()

	d := <-aCh
	if d.Addr != "::1" {
		t.Fatalf("dest addr = %q, want %q", d.Addr, "::1")
	}
	if d.Port != 443 {
		t.Fatalf("dest port = %d, want 443", d.Port)
	}
}

func TestMux_OpenDomainAddress(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Destination, 1)
	go func() {
		s, d, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer s.Close()
		aCh <- d
	}()

	cs, err := client.Open(ctx, "example.com", 8080)
	if err != nil {
		t.Fatalf("Open domain: %v", err)
	}
	defer cs.Close()

	d := <-aCh
	if d.Addr != "example.com" {
		t.Fatalf("dest addr = %q, want %q", d.Addr, "example.com")
	}
	if d.Port != 8080 {
		t.Fatalf("dest port = %d, want 8080", d.Port)
	}
}

func TestMux_ServerHalfClose(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		aCh <- s
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cs.Close()

	ss := <-aCh
	defer ss.Close()

	// Server writes then half-closes.
	go func() {
		ss.Write([]byte("server-data"))
		if cw, ok := ss.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	buf := make([]byte, 64)
	n, err := cs.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "server-data" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "server-data")
	}

	// Client should get EOF after server half-close.
	_, err = cs.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF after server half-close, got %v", err)
	}
}

func TestMux_LargePayloadMultiChunk(t *testing.T) {
	t.Parallel()
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	aCh := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		aCh <- s
	}()

	cs, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cs.Close()

	ss := <-aCh
	defer ss.Close()

	// Write 3x MaxPayloadSize to exercise multi-chunk splitting in stream.Write.
	payload := make([]byte, framing.MaxPayloadSize*3)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	go func() {
		cs.Write(payload)
		cs.Close()
	}()

	got, err := io.ReadAll(ss)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: len got=%d want=%d", len(got), len(payload))
	}
}

func TestMux_OpenCancelledContext(t *testing.T) {
	t.Parallel()
	client, _ := setupMuxPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.Open(ctx, "127.0.0.1", 80)
	if err == nil {
		t.Fatal("Open with cancelled context should return error")
	}
}
