package proxy

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"ghost/internal/framing"
	"ghost/internal/mux"
	"ghost/internal/shaping"
)

// benchMockStream wraps net.Conn to satisfy the Stream interface.
type benchMockStream struct {
	net.Conn
	id uint32
}

func (m *benchMockStream) ID() uint32 { return m.id }

// benchEchoServer starts a TCP echo server and returns its address.
func benchEchoServer(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// benchSocks5Handshake performs the client side of a SOCKS5 handshake.
func benchSocks5Handshake(b *testing.B, conn net.Conn) {
	b.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		b.Fatalf("write handshake: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		b.Fatalf("read handshake reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		b.Fatalf("handshake reply = %x, want [05 00]", reply)
	}
}

// benchSocks5Connect sends a SOCKS5 CONNECT request for an IPv4 address.
func benchSocks5Connect(b *testing.B, conn net.Conn, ip net.IP, port uint16) {
	b.Helper()
	ip4 := ip.To4()
	if ip4 == nil {
		b.Fatal("requires IPv4")
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip4...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		b.Fatalf("write connect: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		b.Fatalf("read connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		b.Fatalf("connect reply rep = 0x%02x, want 0x00", resp[1])
	}
}

func BenchmarkSOCKS5_Relay(b *testing.B) {
	echoAddr := benchEchoServer(b)
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.ParseUint(echoPortStr, 10, 16)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var streamID uint32
	opener := func(_ context.Context, addr string, port uint16) (Stream, error) {
		conn, err := net.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(int(port))))
		if err != nil {
			return nil, err
		}
		streamID++
		return &benchMockStream{Conn: conn, id: streamID}, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	b.Cleanup(func() { srv.Close() })

	srvAddr := benchWaitForListener(b, srv)

	data := make([]byte, 1024)
	readBuf := make([]byte, 1024)

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", srvAddr)
		if err != nil {
			b.Fatal(err)
		}
		benchSocks5Handshake(b, conn)
		benchSocks5Connect(b, conn, net.ParseIP(echoHost), uint16(echoPort))

		if _, err := conn.Write(data); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, readBuf); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		conn.Close()
	}
}

// benchWaitForListener polls until the socks5Server listener is set.
func benchWaitForListener(b *testing.B, srv *socks5Server) string {
	b.Helper()
	for i := 0; i < 3000; i++ {
		srv.mu.Lock()
		ln := srv.listener
		srv.mu.Unlock()
		if ln != nil {
			return ln.Addr().String()
		}
		time.Sleep(time.Millisecond)
	}
	b.Fatal("socks5 listener did not start in time")
	return ""
}

func BenchmarkPipeline_Throughput(b *testing.B) {
	// Create a mux pair connected via io.Pipe with passthrough shaping.
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	// Client side: writes go upstream, reads come downstream.
	clientEncWriter := &framing.EncoderWriter{Enc: framing.NewEncoder(upW)}
	clientDecReader := &framing.DecoderReader{Dec: framing.NewDecoder(downR)}

	// Wrap with passthrough shaping (PadderFrameWriter + UnpadderFrameReader).
	clientWriter := &shaping.PadderFrameWriter{
		Padder: &shaping.PassthroughPadder{},
		Next:   clientEncWriter,
	}
	clientReader := &shaping.UnpadderFrameReader{
		Padder: &shaping.PassthroughPadder{},
		Src:    clientDecReader,
	}

	// Server side: reads come upstream, writes go downstream.
	serverEncWriter := &framing.EncoderWriter{Enc: framing.NewEncoder(downW)}
	serverDecReader := &framing.DecoderReader{Dec: framing.NewDecoder(upR)}

	serverWriter := &shaping.PadderFrameWriter{
		Padder: &shaping.PassthroughPadder{},
		Next:   serverEncWriter,
	}
	serverReader := &shaping.UnpadderFrameReader{
		Padder: &shaping.PassthroughPadder{},
		Src:    serverDecReader,
	}

	client := mux.NewClientMux(clientWriter, clientReader)
	server := mux.NewServerMux(serverWriter, serverReader)

	defer func() {
		client.Close()
		server.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
	}()

	ctx := context.Background()
	data := make([]byte, 1024)
	readBuf := make([]byte, 1024)

	// Server accepts stream and echoes data.
	var once sync.Once
	accepted := make(chan struct{})
	go func() {
		s, _, err := server.Accept(ctx)
		if err != nil {
			return
		}
		once.Do(func() { close(accepted) })
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

	stream, err := client.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		b.Fatal(err)
	}
	<-accepted

	// TODO: full pipeline benchmark requires cmd/ wiring with transport.Conn,
	// auth, and TLS. This version measures mux + shaping (passthrough) overhead
	// which covers the in-process hot path: mux → shaping → framing → pipe.

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(stream, readBuf); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	stream.Close()
}
