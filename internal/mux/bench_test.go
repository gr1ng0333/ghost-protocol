package mux

import (
	"context"
	"io"
	"sync"
	"testing"

	"ghost/internal/framing"
)

// benchMuxPair creates a connected ClientMux and ServerMux for benchmarks.
// The caller must close both muxes and all pipes when done.
func benchMuxPair(b *testing.B) (ClientMux, ServerMux, func()) {
	b.Helper()

	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	client := NewClientMux(
		&framing.EncoderWriter{Enc: framing.NewEncoder(upW)},
		&framing.DecoderReader{Dec: framing.NewDecoder(downR)},
	)
	server := NewServerMux(
		&framing.EncoderWriter{Enc: framing.NewEncoder(downW)},
		&framing.DecoderReader{Dec: framing.NewDecoder(upR)},
	)

	cleanup := func() {
		client.Close()
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	}

	return client, server, cleanup
}

func BenchmarkMux_StreamWrite(b *testing.B) {
	client, server, cleanup := benchMuxPair(b)
	defer cleanup()

	ctx := context.Background()
	data := make([]byte, 1024)

	// Accept server-side stream in background and drain it.
	accepted := make(chan struct{})
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			return
		}
		close(accepted)
		io.Copy(io.Discard, s)
	}()

	stream, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		b.Fatal(err)
	}
	<-accepted

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(data); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	stream.Close()
}

func BenchmarkMux_StreamReadWrite(b *testing.B) {
	client, server, cleanup := benchMuxPair(b)
	defer cleanup()

	ctx := context.Background()
	data := make([]byte, 1024)
	readBuf := make([]byte, 1024)

	// Server accepts and echoes data back.
	accepted := make(chan Stream, 1)
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			return
		}
		accepted <- s
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			if _, err := s.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	clientStream, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		b.Fatal(err)
	}
	<-accepted

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := clientStream.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(clientStream, readBuf); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	clientStream.Close()
}

func BenchmarkMux_ConcurrentStreams(b *testing.B) {
	client, server, cleanup := benchMuxPair(b)
	defer cleanup()

	ctx := context.Background()
	const numStreams = 10
	data := make([]byte, 1024)

	// Server accepts and drains all streams.
	var serverWg sync.WaitGroup
	serverWg.Add(numStreams)
	go func() {
		for i := 0; i < numStreams; i++ {
			s, _, err := server.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer serverWg.Done()
				io.Copy(io.Discard, s)
			}()
		}
	}()

	// Open all streams.
	streams := make([]Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		s, err := client.Open(ctx, "127.0.0.1", uint16(8000+i))
		if err != nil {
			b.Fatal(err)
		}
		streams[i] = s
	}

	b.SetBytes(int64(numStreams * 1024))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for _, s := range streams {
			go func(s Stream) {
				defer wg.Done()
				s.Write(data)
			}(s)
		}
		wg.Wait()
	}

	b.StopTimer()
	for _, s := range streams {
		s.Close()
	}
	serverWg.Wait()
}
