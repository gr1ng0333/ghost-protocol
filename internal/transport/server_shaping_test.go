package transport

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/shaping"
)

// ---------- serverStatsProvider unit tests ----------

func TestServerStatsProvider(t *testing.T) {
	p := &serverStatsProvider{}

	if got := p.ActiveStreamCount(); got != 0 {
		t.Fatalf("ActiveStreamCount = %d, want 0", got)
	}
	if got := p.TotalBytesSent(); got != 0 {
		t.Fatalf("TotalBytesSent = %d, want 0", got)
	}
	if got := p.TotalBytesRecv(); got != 0 {
		t.Fatalf("TotalBytesRecv = %d, want 0", got)
	}

	p.activeStreams.Add(3)
	p.bytesSent.Add(1024)
	p.bytesRecv.Add(2048)

	if got := p.ActiveStreamCount(); got != 3 {
		t.Fatalf("ActiveStreamCount = %d, want 3", got)
	}
	if got := p.TotalBytesSent(); got != 1024 {
		t.Fatalf("TotalBytesSent = %d, want 1024", got)
	}
	if got := p.TotalBytesRecv(); got != 2048 {
		t.Fatalf("TotalBytesRecv = %d, want 2048", got)
	}

	p.activeStreams.Add(-1)
	if got := p.ActiveStreamCount(); got != 2 {
		t.Fatalf("ActiveStreamCount after decrement = %d, want 2", got)
	}
}

// ---------- Fallback TLS termination test ----------

func TestHandleFallback_TLSTermination(t *testing.T) {
	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Start a plain HTTP fallback server (simulates Caddy on :8080).
	fallbackLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	defer fallbackLn.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback-ok"))
	})
	fallbackSrv := &http.Server{Handler: mux}
	go fallbackSrv.Serve(fallbackLn)
	defer fallbackSrv.Close()

	// Create ghost server with TLS config.
	serverKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, nil)
	cfg := &config.ServerConfig{
		Domain:   "localhost",
		Fallback: config.FallbackConfig{Addr: fallbackLn.Addr().String()},
	}
	srv := NewServer(cfg, cert, sa, nil).(*ghostServer)

	// Start the server.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", fallbackLn.Addr().String())
	time.Sleep(100 * time.Millisecond)

	srv.mu.Lock()
	srvAddr := srv.listener.Addr().String()
	srv.mu.Unlock()

	// Connect with a normal TLS client (not authenticated → fallback path).
	tlsConn, err := tls.Dial("tcp", srvAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	// Send an HTTP request over the TLS connection.
	req, _ := http.NewRequest("GET", "http://localhost/", nil)
	req.Write(tlsConn)

	// Read the response.
	buf := make([]byte, 4096)
	tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := tlsConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}

	response := string(buf[:n])
	if len(response) == 0 {
		t.Fatal("empty response from fallback")
	}
	// Should contain the fallback response body.
	if !containsSubstring(response, "fallback-ok") {
		t.Errorf("response does not contain 'fallback-ok': %q", response)
	}

	cancel()
	srv.Close()
}

// ---------- Per-session shaping lifecycle tests ----------

func TestHandleGhost_PerSessionShapingCleanup(t *testing.T) {
	// Verify that cleanup function is wired: when a session is removed,
	// cover traffic and stats updater contexts are cancelled.

	sm := NewSessionManager(10, 5*time.Minute, slog.Default())

	// Register a mock session with a cleanup that sets a flag.
	var cleaned atomic.Bool
	mockPipeline := &mockCloser{}
	err := sm.Register("test-sess", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 100}, mockPipeline, func() {
		cleaned.Store(true)
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if sm.Count() != 1 {
		t.Fatalf("session count = %d, want 1", sm.Count())
	}

	// Remove triggers cleanup.
	sm.Remove("test-sess")

	if !cleaned.Load() {
		t.Fatal("cleanup function was not called on Remove")
	}
	if sm.Count() != 0 {
		t.Fatalf("session count after remove = %d, want 0", sm.Count())
	}
}

func TestSessionManager_MaxSessionsRejectsConnection(t *testing.T) {
	sm := NewSessionManager(1, 5*time.Minute, slog.Default())

	err := sm.Register("sess-1", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}, &mockCloser{}, nil)
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	err = sm.Register("sess-2", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2}, &mockCloser{}, nil)
	if err == nil {
		t.Fatal("expected ErrMaxSessions for second registration")
	}
	if err.Error() == "" {
		t.Fatal("error message should not be empty")
	}

	sm.Remove("sess-1")
}

func TestGhostHandler_TouchOnActivity(t *testing.T) {
	sm := NewSessionManager(10, 5*time.Minute, slog.Default())

	// Register a session.
	err := sm.Register("touch-test", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}, &mockCloser{}, nil)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer sm.Remove("touch-test")

	// Create a handler with session manager wired in.
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	binding := []byte("test-binding")

	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	defer func() { upR.Close(); upW.Close(); downR.Close(); downW.Close() }()

	handler := newGhostHandler(sa, sharedSecret, binding, upW, downR, "/api/upload", "/api/download", "")
	handler.sessionMgr = sm
	handler.sessionID = "touch-test"

	// Record time before request.
	sess := sm.Get("touch-test")
	if sess == nil {
		t.Fatal("session not found")
	}
	beforeTouch := sess.lastActive

	// Small delay so Touch creates a measurably different timestamp.
	time.Sleep(10 * time.Millisecond)

	// An invalid token request won't Touch (returns Forbidden before Touch).
	// A valid token request WILL Touch.
	token := auth.DeriveSessionToken(sharedSecret, binding)

	// Send a POST with valid token — this should call Touch.
	go func() {
		buf := make([]byte, 5)
		io.ReadFull(upR, buf)
	}()

	req := newHTTPRequest(t, "POST", "/api/test", "hello", token)
	rr := newRecorder()
	handler.ServeHTTP(rr, req)

	// Verify Touch was called.
	sess = sm.Get("touch-test")
	if sess == nil {
		t.Fatal("session not found after Touch")
	}
	if !sess.lastActive.After(beforeTouch) {
		t.Error("lastActive was not updated by Touch")
	}
}

func TestNewServerWithSessions_Constructor(t *testing.T) {
	cfg := &config.ServerConfig{
		Domain: "test.local",
	}
	cert, _ := GenerateSelfSignedCert("test.local")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	serverKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, nil)
	sm := NewSessionManager(10, 5*time.Minute, slog.Default())

	// Should not panic with nil profile.
	srv := NewServerWithSessions(cfg, tlsConfig, sa, sm, nil, shaping.ModeBalanced, false)
	if srv == nil {
		t.Fatal("NewServerWithSessions returned nil")
	}

	gs := srv.(*ghostServer)
	if gs.sessionMgr != sm {
		t.Error("sessionMgr not set correctly")
	}
	if gs.tlsConfig != tlsConfig {
		t.Error("tlsConfig not set correctly")
	}
	if gs.profile != nil {
		t.Error("profile should be nil")
	}
	if gs.shapingMode != shaping.ModeBalanced {
		t.Errorf("shapingMode = %v, want ModeBalanced", gs.shapingMode)
	}
}

func TestNewServer_BackwardsCompatible(t *testing.T) {
	cfg := &config.ServerConfig{Domain: "test.local"}
	cert, _ := GenerateSelfSignedCert("test.local")
	serverKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, nil)

	// Old-style constructor should still work.
	srv := NewServer(cfg, cert, sa, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}

	gs := srv.(*ghostServer)
	if gs.tlsConfig == nil {
		t.Fatal("tlsConfig should be set from certificate")
	}
	if len(gs.tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(gs.tlsConfig.Certificates))
	}
	if gs.sessionMgr != nil {
		t.Error("sessionMgr should be nil for legacy constructor")
	}
	if gs.profile != nil {
		t.Error("profile should be nil for legacy constructor")
	}
}

// ---------- Helpers ----------

type mockCloser struct {
	closed atomic.Bool
}

func (m *mockCloser) Close() error {
	m.closed.Store(true)
	return nil
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && searchSubstring(s, sub))
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func newHTTPRequest(t *testing.T, method, path, body, token string) *http.Request {
	t.Helper()
	var bodyR io.Reader
	if body != "" {
		bodyR = stringsReader(body)
	}
	req, err := http.NewRequest(method, path, bodyR)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	return req
}

type stringsReaderType struct {
	s   string
	off int
}

func stringsReader(s string) *stringsReaderType { return &stringsReaderType{s: s} }

func (r *stringsReaderType) Read(p []byte) (int, error) {
	if r.off >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.off:])
	r.off += n
	return n, nil
}

type responseRecorder struct {
	code    int
	headers http.Header
	body    []byte
}

func newRecorder() *responseRecorder {
	return &responseRecorder{headers: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header  { return r.headers }
func (r *responseRecorder) WriteHeader(code int) { r.code = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}
