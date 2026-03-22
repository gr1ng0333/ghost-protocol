package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/mux"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// testConn implements Conn using standard Go HTTP/2 (golang.org/x/net/http2)
// with InsecureSkipVerify for self-signed test certificates.
type testConn struct {
	h2cc    *http2.ClientConn
	rawConn net.Conn
	baseURL string
	token   string
}

func (c *testConn) Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-Token", c.token)
	resp, err := c.h2cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *testConn) Recv(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Session-Token", c.token)
	resp, err := c.h2cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *testConn) Close() error { return c.rawConn.Close() }
func (c *testConn) Alive() bool  { return true }

// testDialGhost connects to a Ghost server using uTLS with InsecureSkipVerify,
// injects the SessionID, derives the session token via EKM, and returns a Conn.
// Follows the same pattern as authTestConn but returns a Conn interface.
func testDialGhost(ctx context.Context, addr string, ca auth.ClientAuth) (Conn, error) {
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("testDial: tcp: %w", err)
	}

	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("testDial: build handshake: %w", err)
	}

	random := uconn.HandshakeState.Hello.Random
	sid, err := ca.InjectSessionID(random)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("testDial: inject session ID: %w", err)
	}
	uconn.HandshakeState.Hello.SessionId = sid
	if len(uconn.HandshakeState.Hello.Raw) < 39+len(sid) {
		rawConn.Close()
		return nil, fmt.Errorf("testDial: ClientHello Raw too short")
	}
	copy(uconn.HandshakeState.Hello.Raw[39:39+len(sid)], sid)

	// Fix Chrome preset renegotiation so ExportKeyingMaterial works.
	for _, ext := range uconn.Extensions {
		if ri, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			ri.Renegotiation = utls.RenegotiateNever
			break
		}
	}
	if err := uconn.ApplyConfig(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("testDial: apply config: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(deadline)
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("testDial: TLS handshake: %w", err)
	}
	rawConn.SetDeadline(time.Time{})

	cs := uconn.ConnectionState()
	binding, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("testDial: EKM: %w", err)
	}
	token, err := ca.DeriveSessionToken(binding)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("testDial: derive token: %w", err)
	}

	h2t := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	h2cc, err := h2t.NewClientConn(uconn)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("testDial: h2 client conn: %w", err)
	}

	return &testConn{
		h2cc:    h2cc,
		rawConn: uconn,
		baseURL: "https://localhost",
		token:   token,
	}, nil
}

// tunnelTestEnv sets up a complete Ghost tunnel environment:
// generates auth keys, starts a Ghost server, and returns the ClientAuth,
// shared secret, and Ghost server address.
func tunnelTestEnv(t *testing.T) (ca auth.ClientAuth, sharedSecret [32]byte, ghostAddr string) {
	t.Helper()

	clientKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca, err = auth.NewClientAuth(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err = auth.SharedSecret(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	_, ghostAddr = startAuthServer(t, sa, "")
	return
}

// startMockDest starts a TCP server that calls handler for each accepted connection.
func startMockDest(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

// splitHostPort splits "host:port" into host string and port uint16.
func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}

// TestTunnel_EndToEnd validates the complete tunnel:
// client → uTLS → HTTP/2 POST → Ghost server → mux → framing → net.Dial(mock)
// → mock reads → mock replies → framing → mux → HTTP/2 GET → client reads.
func TestTunnel_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, secret, ghostAddr := tunnelTestEnv(t)

	// Mock destination: read once, reply with "REPLY:" prefix, close.
	mockAddr := startMockDest(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		c.Write(append([]byte("REPLY:"), buf[:n]...))
	})
	host, port := splitHostPort(t, mockAddr)

	conn, err := testDialGhost(ctx, ghostAddr, ca)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	up, down := mux.DerivePaths(secret)
	pipe, err := mux.NewClientPipeline(ctx, conn, up, down)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}
	defer pipe.Close()

	stream, err := pipe.Mux.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stream.Close()

	msg := []byte("hello through ghost")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	want := "REPLY:hello through ghost"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}
}

// TestTunnel_MultipleStreams opens 3 streams through the same tunnel to
// the same mock server and verifies each gets its own independent reply.
func TestTunnel_MultipleStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, secret, ghostAddr := tunnelTestEnv(t)

	mockAddr := startMockDest(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		c.Write(append([]byte("REPLY:"), buf[:n]...))
	})
	host, port := splitHostPort(t, mockAddr)

	conn, err := testDialGhost(ctx, ghostAddr, ca)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	up, down := mux.DerivePaths(secret)
	pipe, err := mux.NewClientPipeline(ctx, conn, up, down)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}
	defer pipe.Close()

	msgs := []string{"msg-alpha", "msg-beta", "msg-gamma"}
	streams := make([]mux.Stream, len(msgs))

	for i, m := range msgs {
		s, err := pipe.Mux.Open(ctx, host, port)
		if err != nil {
			t.Fatalf("Open[%d]: %v", i, err)
		}
		defer s.Close()
		streams[i] = s
		if _, err := s.Write([]byte(m)); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}

	for i, m := range msgs {
		want := "REPLY:" + m
		got := make([]byte, len(want))
		if _, err := io.ReadFull(streams[i], got); err != nil {
			t.Fatalf("ReadFull[%d]: %v", i, err)
		}
		if string(got) != want {
			t.Fatalf("reply[%d] = %q, want %q", i, got, want)
		}
	}
}

// TestTunnel_StreamClose verifies that closing a stream propagates through
// the full tunnel and that the mux remains functional afterwards.
func TestTunnel_StreamClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, secret, ghostAddr := tunnelTestEnv(t)

	mockClosed := make(chan struct{}, 10)
	mockAddr := startMockDest(t, func(c net.Conn) {
		defer c.Close()
		defer func() { mockClosed <- struct{}{} }()
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		c.Write(append([]byte("REPLY:"), buf[:n]...))
		// Block until the peer closes our connection.
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		c.Read(make([]byte, 1))
	})
	host, port := splitHostPort(t, mockAddr)

	conn, err := testDialGhost(ctx, ghostAddr, ca)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	up, down := mux.DerivePaths(secret)
	pipe, err := mux.NewClientPipeline(ctx, conn, up, down)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}
	defer pipe.Close()

	// Stream 1: write, read reply, then close.
	s1, err := pipe.Mux.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("Open s1: %v", err)
	}
	if _, err := s1.Write([]byte("close-test")); err != nil {
		t.Fatalf("Write s1: %v", err)
	}
	want := "REPLY:close-test"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(s1, got); err != nil {
		t.Fatalf("ReadFull s1: %v", err)
	}
	if string(got) != want {
		t.Fatalf("s1 reply = %q, want %q", got, want)
	}
	s1.Close()

	// Verify mock's connection was closed (FrameClose propagated).
	select {
	case <-mockClosed:
		// Good.
	case <-time.After(5 * time.Second):
		t.Fatal("mock did not see connection close after stream.Close()")
	}

	// Stream 2: verify mux is still functional after stream close.
	s2, err := pipe.Mux.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("Open s2 after close: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Write([]byte("after-close")); err != nil {
		t.Fatalf("Write s2: %v", err)
	}
	want2 := "REPLY:after-close"
	got2 := make([]byte, len(want2))
	if _, err := io.ReadFull(s2, got2); err != nil {
		t.Fatalf("ReadFull s2: %v", err)
	}
	if string(got2) != want2 {
		t.Fatalf("s2 reply = %q, want %q", got2, want2)
	}
}

// TestTunnel_LargePayload sends 100KB of deterministic data through the
// tunnel and verifies byte-for-byte integrity after echoing.
func TestTunnel_LargePayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, secret, ghostAddr := tunnelTestEnv(t)

	// Echo mock: copies all data back until the sender closes.
	mockAddr := startMockDest(t, func(c net.Conn) {
		defer c.Close()
		io.Copy(c, c)
	})
	host, port := splitHostPort(t, mockAddr)

	conn, err := testDialGhost(ctx, ghostAddr, ca)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	up, down := mux.DerivePaths(secret)
	pipe, err := mux.NewClientPipeline(ctx, conn, up, down)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}
	defer pipe.Close()

	stream, err := pipe.Mux.Open(ctx, host, port)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stream.Close()

	const size = 100 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251) // prime modulus for pattern variation
	}

	// Write and read concurrently: the echo mock reads upstream data and
	// writes it back, so both directions must be active simultaneously
	// to avoid deadlock on large payloads.
	var wg sync.WaitGroup
	var writeErr, readErr error
	result := make([]byte, size)

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, writeErr = stream.Write(payload)
	}()
	go func() {
		defer wg.Done()
		_, readErr = io.ReadFull(stream, result)
	}()
	wg.Wait()

	if writeErr != nil {
		t.Fatalf("Write: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("ReadFull: %v", readErr)
	}
	if !bytes.Equal(payload, result) {
		for i := range payload {
			if payload[i] != result[i] {
				t.Fatalf("data mismatch at byte %d: got 0x%02x, want 0x%02x", i, result[i], payload[i])
			}
		}
	}
}

// TestTunnel_WrongAuth_NoTunnel verifies that a client with the wrong key
// cannot establish a tunnel through the Ghost server.
func TestTunnel_WrongAuth_NoTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Server only knows clientA's public key.
	clientA_KP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientA_KP.Public})
	if err != nil {
		t.Fatal(err)
	}

	// Start Ghost server with no fallback.
	_, ghostAddr := startAuthServer(t, sa, "")

	// Dialer uses clientB (wrong key).
	clientB_KP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongCA, err := auth.NewClientAuth(clientB_KP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	// Dial should fail — wrong SessionID routes to fallback, no fallback closes conn.
	_, err = testDialGhost(ctx, ghostAddr, wrongCA)
	if err == nil {
		t.Fatal("Dial with wrong auth succeeded, want error")
	}
}
