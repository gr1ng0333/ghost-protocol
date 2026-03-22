package mux

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"ghost/internal/framing"
)

// setupMuxPair creates a connected ClientMux + ServerMux for testing.
// Uses two io.Pipes: one for client→server, one for server→client.
func setupMuxPair(t *testing.T) (ClientMux, ServerMux) {
	t.Helper()

	// Client writes → Server reads (upstream)
	upR, upW := io.Pipe()
	// Server writes → Client reads (downstream)
	downR, downW := io.Pipe()

	clientEnc := framing.NewEncoder(upW)
	clientDec := framing.NewDecoder(downR)

	serverEnc := framing.NewEncoder(downW)
	serverDec := framing.NewDecoder(upR)

	client := NewClientMux(clientEnc, clientDec)
	server := NewServerMux(serverEnc, serverDec)

	t.Cleanup(func() {
		client.Close()
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	})

	return client, server
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestClientMux_OpenStream(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	// Open and Accept must happen concurrently.
	type acceptRes struct {
		stream Stream
		dest   Destination
		err    error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		s, d, err := server.Accept(ctx)
		ch <- acceptRes{s, d, err}
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	res := <-ch
	if res.err != nil {
		t.Fatalf("server.Accept: %v", res.err)
	}

	if res.dest.Addr != "example.com" || res.dest.Port != 80 {
		t.Fatalf("destination = %+v, want {example.com 80}", res.dest)
	}
	if cs.ID()%2 != 1 {
		t.Fatalf("client stream ID %d is not odd", cs.ID())
	}
	if cs.ID() != 1 {
		t.Fatalf("first client stream ID = %d, want 1", cs.ID())
	}
	if res.stream.ID() != cs.ID() {
		t.Fatalf("server stream ID %d != client stream ID %d", res.stream.ID(), cs.ID())
	}
}

func TestClientMux_SendReceive(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- s
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	ss := <-ch

	// Client → Server
	if _, err := cs.Write([]byte("hello from client")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 128)
	n, err := ss.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != "hello from client" {
		t.Fatalf("server got %q, want %q", string(buf[:n]), "hello from client")
	}

	// Server → Client
	if _, err := ss.Write([]byte("hello from server")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	n, err = cs.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "hello from server" {
		t.Fatalf("client got %q, want %q", string(buf[:n]), "hello from server")
	}
}

func TestClientMux_MultipleStreams(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	const count = 5

	type streamPair struct {
		client Stream
		server Stream
		dest   Destination
	}

	// Accept in background, collecting results.
	serverStreams := make(chan streamPair, count)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			s, d, err := server.Accept(ctx)
			if err != nil {
				t.Errorf("server.Accept[%d]: %v", i, err)
				return
			}
			serverStreams <- streamPair{server: s, dest: d}
		}
	}()

	// Open 5 streams.
	clientStreams := make([]Stream, count)
	for i := 0; i < count; i++ {
		cs, err := client.Open(ctx, "example.com", uint16(80+i))
		if err != nil {
			t.Fatalf("client.Open[%d]: %v", i, err)
		}
		clientStreams[i] = cs
	}

	wg.Wait()
	close(serverStreams)

	// Map server streams by ID.
	serverByID := make(map[uint32]Stream)
	for sp := range serverStreams {
		serverByID[sp.server.ID()] = sp.server
	}

	// Verify stream IDs are odd and unique, and write/read each.
	seenIDs := make(map[uint32]bool)
	for i, cs := range clientStreams {
		id := cs.ID()
		if id%2 != 1 {
			t.Errorf("stream %d: ID %d is not odd", i, id)
		}
		if seenIDs[id] {
			t.Errorf("stream %d: duplicate ID %d", i, id)
		}
		seenIDs[id] = true

		ss, ok := serverByID[id]
		if !ok {
			t.Fatalf("stream %d: no server stream for ID %d", i, id)
		}

		msg := []byte("msg-" + string(rune('A'+i)))
		if _, err := cs.Write(msg); err != nil {
			t.Fatalf("stream %d write: %v", i, err)
		}
		buf := make([]byte, 64)
		n, err := ss.Read(buf)
		if err != nil {
			t.Fatalf("stream %d read: %v", i, err)
		}
		if string(buf[:n]) != string(msg) {
			t.Fatalf("stream %d: got %q, want %q", i, string(buf[:n]), string(msg))
		}
	}

	// Expected IDs: 1, 3, 5, 7, 9
	expectedIDs := []uint32{1, 3, 5, 7, 9}
	for _, eid := range expectedIDs {
		if !seenIDs[eid] {
			t.Errorf("expected stream ID %d not found", eid)
		}
	}

	stats := client.Stats()
	if stats.ActiveStreams != count {
		t.Errorf("ActiveStreams = %d, want %d", stats.ActiveStreams, count)
	}
}

func TestClientMux_CloseStream(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- s
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	ss := <-ch

	// Client closes its stream.
	if err := cs.Close(); err != nil {
		t.Fatalf("client stream Close: %v", err)
	}

	// Server should get EOF on Read.
	buf := make([]byte, 64)
	_, err = ss.Read(buf)
	if err != io.EOF {
		t.Fatalf("server read after client close: got err %v, want io.EOF", err)
	}
}

func TestServerMux_AcceptStream(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan struct {
		Stream
		Destination
	}, 1)
	go func() {
		s, d, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- struct {
			Stream
			Destination
		}{s, d}
	}()

	_, err := client.Open(ctx, "10.0.0.1", 443)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	res := <-ch
	if res.Destination.Addr != "10.0.0.1" || res.Destination.Port != 443 {
		t.Fatalf("destination = %+v, want {10.0.0.1 443}", res.Destination)
	}

	// Verify stream is usable.
	if _, err := res.Stream.Write([]byte("server-reply")); err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func TestServerMux_RouteData(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	const count = 3
	messages := []string{"stream1", "stream2", "stream3"}

	// Accept streams in background.
	serverStreams := make(chan Stream, count)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			s, _, err := server.Accept(ctx)
			if err != nil {
				t.Errorf("server.Accept[%d]: %v", i, err)
				return
			}
			serverStreams <- s
		}
	}()

	// Open streams.
	clientStreams := make([]Stream, count)
	for i := 0; i < count; i++ {
		cs, err := client.Open(ctx, "example.com", uint16(80+i))
		if err != nil {
			t.Fatalf("client.Open[%d]: %v", i, err)
		}
		clientStreams[i] = cs
	}

	wg.Wait()
	close(serverStreams)

	// Map server streams by ID.
	serverByID := make(map[uint32]Stream)
	for s := range serverStreams {
		serverByID[s.ID()] = s
	}

	// Write unique messages on each client stream.
	for i, cs := range clientStreams {
		if _, err := cs.Write([]byte(messages[i])); err != nil {
			t.Fatalf("client write[%d]: %v", i, err)
		}
	}

	// Read from corresponding server streams and verify no cross-contamination.
	for i, cs := range clientStreams {
		ss := serverByID[cs.ID()]
		buf := make([]byte, 64)
		n, err := ss.Read(buf)
		if err != nil {
			t.Fatalf("server read[%d]: %v", i, err)
		}
		if string(buf[:n]) != messages[i] {
			t.Fatalf("stream %d: got %q, want %q", i, string(buf[:n]), messages[i])
		}
	}
}

func TestMux_Bidirectional(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- s
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	ss := <-ch

	const size = 1000
	clientData := make([]byte, size)
	serverData := make([]byte, size)
	for i := range clientData {
		clientData[i] = byte(i % 251) // prime to avoid simple patterns
	}
	for i := range serverData {
		serverData[i] = byte((i + 127) % 251)
	}

	var wg sync.WaitGroup
	var clientReadErr, serverReadErr error

	// Client writes, server reads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, size)
		total := 0
		for total < size {
			n, err := ss.Read(buf[total:])
			if err != nil {
				serverReadErr = err
				return
			}
			total += n
		}
		for i := 0; i < size; i++ {
			if buf[i] != clientData[i] {
				serverReadErr = io.ErrUnexpectedEOF // signal mismatch
				return
			}
		}
	}()

	// Server writes, client reads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, size)
		total := 0
		for total < size {
			n, err := cs.Read(buf[total:])
			if err != nil {
				clientReadErr = err
				return
			}
			total += n
		}
		for i := 0; i < size; i++ {
			if buf[i] != serverData[i] {
				clientReadErr = io.ErrUnexpectedEOF
				return
			}
		}
	}()

	if _, err := cs.Write(clientData); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := ss.Write(serverData); err != nil {
		t.Fatalf("server write: %v", err)
	}

	wg.Wait()
	if serverReadErr != nil {
		t.Fatalf("server read error: %v", serverReadErr)
	}
	if clientReadErr != nil {
		t.Fatalf("client read error: %v", clientReadErr)
	}
}

func TestMux_LargePayload(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- s
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	ss := <-ch

	const size = 50000 // > MaxPayloadSize (16000), forces chunking
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Write in background (may block until reader drains).
	writeDone := make(chan error, 1)
	go func() {
		_, err := cs.Write(payload)
		writeDone <- err
	}()

	// Read all bytes on server.
	received := make([]byte, size)
	total := 0
	for total < size {
		n, err := ss.Read(received[total:])
		if err != nil {
			t.Fatalf("server read at offset %d: %v", total, err)
		}
		total += n
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Verify data integrity.
	for i := 0; i < size; i++ {
		if received[i] != payload[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, received[i], payload[i])
		}
	}
}

func TestMux_ServerCloseStream(t *testing.T) {
	client, server := setupMuxPair(t)
	ctx := testCtx(t)

	ch := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			t.Errorf("server.Accept: %v", err)
			return
		}
		ch <- s
	}()

	cs, err := client.Open(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	ss := <-ch

	// Server closes its stream.
	if err := ss.Close(); err != nil {
		t.Fatalf("server stream Close: %v", err)
	}

	// Client should get EOF on Read.
	buf := make([]byte, 64)
	_, err = cs.Read(buf)
	if err != io.EOF {
		t.Fatalf("client read after server close: got err %v, want io.EOF", err)
	}
}

func TestMux_PaddingDiscarded(t *testing.T) {
	// Set up a server mux with pipes we control directly, so we can inject
	// a padding frame without racing with another encoder.
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	serverEnc := framing.NewEncoder(downW)
	serverDec := framing.NewDecoder(upR)
	server := NewServerMux(serverEnc, serverDec)

	t.Cleanup(func() {
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	})

	ctx := testCtx(t)

	// We manually encode frames to the upstream pipe (simulating a client).
	enc := framing.NewEncoder(upW)

	// 1. Inject a padding frame — should be silently discarded.
	go func() {
		_ = enc.Encode(&framing.Frame{
			Type:    framing.FramePadding,
			Padding: []byte{0, 0, 0, 0},
		})

		// 2. Inject a keepalive — also discarded.
		_ = enc.Encode(&framing.Frame{
			Type: framing.FrameKeepAlive,
		})

		// 3. Send a proper FrameOpen.
		payload, _ := framing.EncodeOpenPayload(&framing.OpenPayload{
			Proto:    framing.ProtoTCP,
			AddrType: framing.AddrDomain,
			Addr:     "example.com",
			Port:     443,
		})
		_ = enc.Encode(&framing.Frame{
			Type:     framing.FrameOpen,
			StreamID: 1,
			Payload:  payload,
		})

		// 4. Send a FrameData with actual content.
		_ = enc.Encode(&framing.Frame{
			Type:     framing.FrameData,
			StreamID: 1,
			Payload:  []byte("after-padding"),
		})
	}()

	// Accept the stream — padding and keepalive should have been skipped.
	ss, dest, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("server.Accept: %v", err)
	}
	if dest.Addr != "example.com" || dest.Port != 443 {
		t.Fatalf("destination = %+v, want {example.com 443}", dest)
	}

	buf := make([]byte, 64)
	n, err := ss.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != "after-padding" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "after-padding")
	}

	// Also drain the downstream pipe so the server's writeLoop doesn't block.
	go func() {
		_, _ = io.Copy(io.Discard, downR)
	}()
}
