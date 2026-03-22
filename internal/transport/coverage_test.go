package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"

	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	xhttp2 "golang.org/x/net/http2"
)

// ==========================================================================
// ghostSession tests — cover ID, RemoteAddr, Receive, Send, Close
// ==========================================================================

func TestGhostSession_Fields(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5555}
	sess := &ghostSession{id: "sess-abc", remoteAddr: addr, done: make(chan struct{})}

	if got := sess.ID(); got != "sess-abc" {
		t.Errorf("ID() = %q, want %q", got, "sess-abc")
	}
	if got := sess.RemoteAddr(); got != addr {
		t.Errorf("RemoteAddr() = %v, want %v", got, addr)
	}
}

func TestGhostSession_ReceiveSend(t *testing.T) {
	sess := &ghostSession{id: "x", remoteAddr: &net.TCPAddr{}, done: make(chan struct{})}

	data, err := sess.Receive(context.Background())
	if data != nil {
		t.Errorf("Receive data = %v, want nil", data)
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Receive err = %v, want ErrNotImplemented", err)
	}

	err = sess.Send(context.Background(), []byte("test"))
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Send err = %v, want ErrNotImplemented", err)
	}
}

func TestGhostSession_CloseIdempotent(t *testing.T) {
	sess := &ghostSession{id: "x", remoteAddr: &net.TCPAddr{}, done: make(chan struct{})}
	if err := sess.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ==========================================================================
// ghostListener tests — cover Accept and Close
// ==========================================================================

func TestGhostListener_AcceptSession(t *testing.T) {
	ch := make(chan Session, 1)
	sess := &ghostSession{id: "l-test", remoteAddr: &net.TCPAddr{}, done: make(chan struct{})}
	ch <- sess

	l := &ghostListener{sessions: ch, done: make(chan struct{})}
	got, err := l.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.ID() != "l-test" {
		t.Errorf("ID = %q, want %q", got.ID(), "l-test")
	}
}

func TestGhostListener_AcceptContextDone(t *testing.T) {
	l := &ghostListener{sessions: make(chan Session), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := l.Accept(ctx)
	if err == nil {
		t.Fatal("Accept should fail with cancelled context")
	}
}

func TestGhostListener_AcceptAfterClose(t *testing.T) {
	l := &ghostListener{sessions: make(chan Session), done: make(chan struct{})}
	l.Close()
	_, err := l.Accept(context.Background())
	if err == nil {
		t.Fatal("Accept should fail after Close")
	}
}

func TestGhostListener_AcceptClosedChannel(t *testing.T) {
	ch := make(chan Session)
	close(ch)
	l := &ghostListener{sessions: ch, done: make(chan struct{})}
	_, err := l.Accept(context.Background())
	if err == nil {
		t.Fatal("Accept should fail on closed sessions channel")
	}
}

func TestGhostListener_CloseIdempotent(t *testing.T) {
	l := &ghostListener{sessions: make(chan Session), done: make(chan struct{})}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ==========================================================================
// NewDialer / Dial error path tests
// ==========================================================================

func TestNewDialer_ReturnsNonNil(t *testing.T) {
	kp, _ := auth.GenKeyPair()
	skp, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(kp.Private, skp.Public)
	d := NewDialer(DefaultChromeH2Config(), ca)
	if d == nil {
		t.Fatal("NewDialer returned nil")
	}
}

func TestDial_TCPFailure(t *testing.T) {
	kp, _ := auth.GenKeyPair()
	skp, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(kp.Private, skp.Public)
	d := NewDialer(DefaultChromeH2Config(), ca)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := d.Dial(ctx, "127.0.0.1:1", "localhost")
	if err == nil {
		t.Fatal("expected error for unreachable port")
	}
	if !strings.Contains(err.Error(), "transport.Dial") {
		t.Errorf("error = %v, want to contain 'transport.Dial'", err)
	}
}

// TestDial_HandshakeFailure exercises the Dial preamble: uTLS client
// creation, BuildHandshakeState, InjectSessionID, SessionID Raw patch,
// renegotiation fix, ApplyConfig — all before the TLS handshake fails
// due to the self-signed cert not being in the OS trust store.
func TestDial_HandshakeFailure(t *testing.T) {
	cert, _ := GenerateSelfSignedCert("localhost")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsSrv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				tlsSrv.Handshake()
			}(conn)
		}
	}()

	kp, _ := auth.GenKeyPair()
	skp, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(kp.Private, skp.Public)
	d := NewDialer(DefaultChromeH2Config(), ca)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = d.Dial(ctx, ln.Addr().String(), "localhost")
	if err == nil {
		t.Fatal("expected TLS handshake error against self-signed cert")
	}
	if !strings.Contains(err.Error(), "transport.Dial") {
		t.Errorf("error = %v, want to contain 'transport.Dial'", err)
	}
}

// ==========================================================================
// h2Conn tests (Send, Recv, Close, Alive) via pipe-based TLS+HTTP/2
// ==========================================================================

// newH2TestConn creates a TLS+HTTP/2 connection pair using net.Pipe.
// Server side uses golang.org/x/net/http2; client side uses fhttp/http2
// (matching the types used in h2Conn).
func newH2TestConn(t *testing.T) (*h2Conn, func()) {
	t.Helper()
	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}

	clientRaw, serverRaw := net.Pipe()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
		tlsConn := tls.Server(serverRaw, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()

		h2srv := &xhttp2.Server{}
		h2srv.ServeConn(tlsConn, &xhttp2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPost:
					body, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Write(body)
				case http.MethodGet:
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Write([]byte("get-response"))
				}
			}),
		})
	}()

	clientTLSCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	tlsClient := tls.Client(clientRaw, clientTLSCfg)
	if err := tlsClient.Handshake(); err != nil {
		clientRaw.Close()
		serverRaw.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}

	h2t := &fhttp2.Transport{}
	h2cc, err := h2t.NewClientConn(tlsClient)
	if err != nil {
		tlsClient.Close()
		<-serverDone
		t.Fatalf("NewClientConn: %v", err)
	}

	conn := &h2Conn{
		cc:      h2cc,
		rawConn: tlsClient,
		baseURL: "https://localhost",
		pho:     []string{":method", ":authority", ":scheme", ":path"},
		token:   "test-token",
	}

	return conn, func() {
		conn.Close()
		<-serverDone
	}
}

func TestH2Conn_SendRecv(t *testing.T) {
	conn, cleanup := newH2TestConn(t)
	defer cleanup()

	ctx := context.Background()

	// Test Send (POST echo).
	body, err := conn.Send(ctx, "/test", []byte("hello-send"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != "hello-send" {
		t.Errorf("Send response = %q, want %q", data, "hello-send")
	}

	// Test Recv (GET).
	rBody, err := conn.Recv(ctx, "/test")
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	rData, _ := io.ReadAll(rBody)
	rBody.Close()
	if string(rData) != "get-response" {
		t.Errorf("Recv response = %q, want %q", rData, "get-response")
	}
}

func TestH2Conn_CloseAndAlive(t *testing.T) {
	conn, _ := newH2TestConn(t)

	// Close the connection.
	err := conn.Close()
	if err != nil {
		t.Logf("Close: %v (may be expected h2 error)", err)
	}

	// After closing, Alive should return false.
	if conn.Alive() {
		t.Error("Alive() = true after Close")
	}
}

func TestH2Conn_Alive_Healthy(t *testing.T) {
	// Use a raw TCP pair to test Alive without HTTP/2 interference.
	client, server := tcpPair(t)
	defer server.Close()
	defer client.Close()

	conn := &h2Conn{rawConn: client}
	if !conn.Alive() {
		t.Error("Alive() = false on open connection")
	}

	server.Close()
	time.Sleep(50 * time.Millisecond) // FIN propagation time
	if conn.Alive() {
		t.Error("Alive() = true after remote close")
	}
}

// ==========================================================================
// Handler edge cases
// ==========================================================================

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("simulated read error") }

func TestGhostHandler_PostReadError(t *testing.T) {
	handler, token, upR, _ := testHandlerSetup(t)
	defer upR.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", errReader{})
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Copy error: handler returns without writing a status, so recorder defaults to 200.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestGhostHandler_UnsupportedMethod(t *testing.T) {
	handler, token, _, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/sync", nil)
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// ==========================================================================
// Router edge cases — nil guards
// ==========================================================================

func TestConnRouter_NilCHI(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	r := newConnRouter(sa)
	mode, _ := r.route(nil)
	if mode != routeFallback {
		t.Errorf("route(nil) = %d, want routeFallback", mode)
	}
}

func TestConnRouter_NilServerAuth(t *testing.T) {
	r := newConnRouter(nil)
	chi := &clientHelloInfo{
		Random:    make([]byte, 32),
		SessionID: make([]byte, 32),
	}
	mode, _ := r.route(chi)
	if mode != routeFallback {
		t.Errorf("route(nil auth) = %d, want routeFallback", mode)
	}
}

// ==========================================================================
// parseClientHello edge cases
// ==========================================================================

func TestParseClientHello_RecordLengthExceedsData(t *testing.T) {
	random := make([]byte, 32)
	raw := buildClientHello(random, nil)
	// Set record length to a value much larger than available data.
	binary.BigEndian.PutUint16(raw[3:5], 0xFFFF)

	_, err := parseClientHello(raw)
	if err == nil {
		t.Fatal("expected error for oversized record length")
	}
}

func TestParseClientHello_SessionIDLengthExceeds(t *testing.T) {
	random := make([]byte, 32)
	raw := buildClientHello(random, nil)
	// Set session ID length to 0xFF — far more data than available.
	raw[43] = 0xFF

	_, err := parseClientHello(raw)
	if err == nil {
		t.Fatal("expected error for oversized session ID length")
	}
}

// ==========================================================================
// handleIncoming edge cases
// ==========================================================================

func newTestGhostServer(t *testing.T) *ghostServer {
	t.Helper()
	cert, _ := GenerateSelfSignedCert("test.local")
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	cfg := &config.ServerConfig{Domain: "test.local"}
	return NewServer(cfg, cert, sa).(*ghostServer)
}

func TestHandleIncoming_PeekFailure(t *testing.T) {
	srv := newTestGhostServer(t)

	// Closing the write end immediately causes EOF on the read end.
	client, server := net.Pipe()
	client.Close()

	// Should log warning and return without panic.
	srv.handleIncoming(context.Background(), server, "")
}

func TestHandleIncoming_ParseFailure(t *testing.T) {
	srv := newTestGhostServer(t)

	client, server := net.Pipe()
	go func() {
		// Send enough non-TLS garbage data to pass the length check
		// but fail the content-type check.
		garbage := make([]byte, 100)
		client.Write(garbage)
		client.Close()
	}()

	// Should log warning and return without panic.
	srv.handleIncoming(context.Background(), server, "")
}

// ==========================================================================
// handleFallback with empty fallback
// ==========================================================================

func TestHandleFallback_EmptyAddr(t *testing.T) {
	srv := newTestGhostServer(t)

	client, server := net.Pipe()
	go func() {
		client.Write([]byte("some data"))
		client.Close()
	}()

	pc, _, err := newPeekConn(server, 100)
	if err != nil {
		t.Fatalf("newPeekConn: %v", err)
	}

	// Empty fallback should close the connection.
	srv.handleFallback(context.Background(), pc, "")
}

// ==========================================================================
// Server.Close idempotent
// ==========================================================================

func TestServerClose_AlreadyClosed(t *testing.T) {
	srv := newTestGhostServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0", "")
	}()
	time.Sleep(100 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second close should be a no-op.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	cancel()
	<-errCh
}

// ==========================================================================
// splice with unreachable backend
// ==========================================================================

func TestSplice_UnreachableBackend(t *testing.T) {
	client, remote := tcpPair(t)
	defer client.Close()

	err := splice(context.Background(), remote, []byte("PEEK"), "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable fallback")
	}
	if !strings.Contains(err.Error(), "splice: dial fallback") {
		t.Errorf("error = %v, want to contain 'splice: dial fallback'", err)
	}
}

// ==========================================================================
// generateSessionID uniqueness
// ==========================================================================

func TestH2Conn_DoubleClose(t *testing.T) {
	conn, _ := newH2TestConn(t)
	conn.Close() // First close succeeds.
	err := conn.Close()
	// Second close should hit at least one error path (rawConn already closed).
	if err == nil {
		t.Log("second Close returned nil (acceptable if h2 absorbed it)")
	}
}

func TestH2Conn_SendAfterClose(t *testing.T) {
	conn, _ := newH2TestConn(t)
	conn.Close()

	_, err := conn.Send(context.Background(), "/test", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Send on closed connection")
	}
	if !strings.Contains(err.Error(), "transport.Send") {
		t.Errorf("error = %v, want to contain 'transport.Send'", err)
	}
}

func TestH2Conn_RecvAfterClose(t *testing.T) {
	conn, _ := newH2TestConn(t)
	conn.Close()

	_, err := conn.Recv(context.Background(), "/test")
	if err == nil {
		t.Fatal("expected error from Recv on closed connection")
	}
	if !strings.Contains(err.Error(), "transport.Recv") {
		t.Errorf("error = %v, want to contain 'transport.Recv'", err)
	}
}

func TestGenerateSessionID_Unique(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		id := generateSessionID()
		if len(id) != 32 {
			t.Fatalf("generateSessionID length = %d, want 32", len(id))
		}
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate sessionID on iteration %d", i)
		}
		ids[id] = struct{}{}
	}
}
