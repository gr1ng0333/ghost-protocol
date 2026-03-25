package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"ghost/internal/auth"
)

func skipIfNoNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("GHOST_NETWORK_TESTS") == "" {
		t.Skip("requires network (set GHOST_NETWORK_TESTS=1 to enable)")
	}
}

func testDialer() Dialer {
	// Generate throwaway key pair for external server tests.
	// Auth won't be verified by external servers, but Dialer requires it.
	clientKP, _ := auth.GenKeyPair()
	serverKP, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(clientKP.Private, serverKP.Public)
	return NewDialer(DefaultChromeH2Config(), ca)
}

func testDial(t *testing.T, addr, sni string) Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := testDialer().Dial(ctx, addr, sni)
	if err != nil {
		t.Fatalf("testDial(%s, %s): %v", addr, sni, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestDefaultChromeH2Config(t *testing.T) {
	cfg := DefaultChromeH2Config()

	if cfg.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize = %d, want 65536", cfg.HeaderTableSize)
	}
	if cfg.EnablePush != 0 {
		t.Errorf("EnablePush = %d, want 0", cfg.EnablePush)
	}
	if cfg.InitialWindowSize != 6291456 {
		t.Errorf("InitialWindowSize = %d, want 6291456", cfg.InitialWindowSize)
	}
	if cfg.MaxHeaderListSize != 262144 {
		t.Errorf("MaxHeaderListSize = %d, want 262144", cfg.MaxHeaderListSize)
	}
	if cfg.WindowUpdateSize != 15663105 {
		t.Errorf("WindowUpdateSize = %d, want 15663105", cfg.WindowUpdateSize)
	}
	wantPHO := []string{":method", ":authority", ":scheme", ":path"}
	if len(cfg.PseudoHeaderOrder) != len(wantPHO) {
		t.Fatalf("PseudoHeaderOrder length = %d, want %d", len(cfg.PseudoHeaderOrder), len(wantPHO))
	}
	for i, v := range wantPHO {
		if cfg.PseudoHeaderOrder[i] != v {
			t.Errorf("PseudoHeaderOrder[%d] = %q, want %q", i, cfg.PseudoHeaderOrder[i], v)
		}
	}
	if cfg.PriorityMode != "none" {
		t.Errorf("PriorityMode = %q, want %q", cfg.PriorityMode, "none")
	}
	if !cfg.ALPSEnabled {
		t.Error("ALPSEnabled = false, want true")
	}
}

func TestDial_Success(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Fatal("conn is nil")
	}
	if !conn.Alive() {
		t.Error("Alive() = false immediately after Dial")
	}
}

func TestDial_InvalidAddr(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "invalid.host.that.does.not.exist.example:443", "invalid.host.that.does.not.exist.example")
	if err == nil {
		conn.Close()
		t.Fatal("expected error for invalid address, got nil")
	}
	if conn != nil {
		t.Error("expected nil conn on error")
	}
}

func TestDial_Timeout(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	// Ensure the context is definitely expired.
	time.Sleep(time.Millisecond)

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err == nil {
		conn.Close()
		t.Fatal("expected error for expired context, got nil")
	}
}

func TestSend_BasicPost(t *testing.T) {
	skipIfNoNetwork(t)

	conn := testDial(t, "httpbin.org:443", "httpbin.org")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body, err := conn.Send(ctx, "/post", []byte("hello ghost"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	resp := string(data)
	if !strings.Contains(resp, "hello ghost") {
		t.Errorf("response does not contain echoed payload:\n%s", resp)
	}
}

func TestRecv_BasicGet(t *testing.T) {
	skipIfNoNetwork(t)

	conn := testDial(t, "httpbin.org:443", "httpbin.org")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body, err := conn.Recv(ctx, "/get")
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	resp := string(data)
	if !strings.Contains(resp, "url") {
		t.Errorf("response does not look like valid httpbin JSON:\n%s", resp)
	}
}

func TestConn_Close(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if !conn.Alive() {
		t.Error("Alive() = false before Close")
	}

	if err := conn.Close(); err != nil {
		t.Logf("Close returned error (may be expected): %v", err)
	}

	if conn.Alive() {
		t.Error("Alive() = true after Close")
	}
}

func TestSend_ClosedConn(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	_, err = conn.Send(ctx, "/test", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Send on closed conn, got nil")
	}
	if !strings.Contains(err.Error(), "transport.Send") {
		t.Errorf("error should contain 'transport.Send', got: %v", err)
	}
}

func TestRecv_ClosedConn(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	_, err = conn.Recv(ctx, "/test")
	if err == nil {
		t.Fatal("expected error from Recv on closed conn, got nil")
	}
	if !strings.Contains(err.Error(), "transport.Recv") {
		t.Errorf("error should contain 'transport.Recv', got: %v", err)
	}
}

func TestDial_TLSHandshakeFailure(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := testDialer()
	// Dial a real address but with a mismatched SNI — TLS handshake should fail.
	conn, err := d.Dial(ctx, "www.google.com:443", "wrong.sni.invalid")
	if err == nil {
		conn.Close()
		t.Fatal("expected TLS handshake error for wrong SNI, got nil")
	}
	if !strings.Contains(err.Error(), "transport.Dial") {
		t.Errorf("error should contain 'transport.Dial', got: %v", err)
	}
}

func TestConn_DoubleClose(t *testing.T) {
	skipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := testDialer()
	conn, err := d.Dial(ctx, "www.google.com:443", "www.google.com")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// First close should succeed (or return expected h2 error).
	if err := conn.Close(); err != nil {
		t.Logf("first Close: %v", err)
	}

	// Second close exercises the rawConn error branch in Close.
	err = conn.Close()
	if err == nil {
		t.Log("second Close returned nil (unexpected but acceptable)")
	} else {
		t.Logf("second Close: %v", err)
	}
}

// TestDial_UsesInjectedNetDialer verifies that h2Dialer uses the NetDialer
// from H2Config when one is provided. The injected dialer's Control function
// returns a sentinel error so no real network connection is needed.
func TestDial_UsesInjectedNetDialer(t *testing.T) {
	var controlCalled bool
	customDialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			controlCalled = true
			// Return a sentinel error to abort immediately — no real I/O needed.
			return fmt.Errorf("sentinel: injected dialer control invoked")
		},
	}

	cfg := DefaultChromeH2Config()
	cfg.NetDialer = customDialer

	clientKP, _ := auth.GenKeyPair()
	serverKP, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(clientKP.Private, serverKP.Public)
	d := NewDialer(cfg, ca)

	_, err := d.Dial(context.Background(), "127.0.0.1:1", "example.com")

	if !controlCalled {
		t.Error("injected NetDialer.Control was not called; expected Dialer to use H2Config.NetDialer")
	}
	if err == nil {
		t.Error("expected an error from the sentinel dialer, got nil")
	}
}

// TestDial_DefaultNetDialer verifies that a nil H2Config.NetDialer falls back
// to a default net.Dialer without panicking. A refused-connection error is
// expected; a nil-pointer dereference is not.
func TestDial_DefaultNetDialer(t *testing.T) {
	cfg := DefaultChromeH2Config()
	// cfg.NetDialer is nil — the zero value.

	clientKP, _ := auth.GenKeyPair()
	serverKP, _ := auth.GenKeyPair()
	ca, _ := auth.NewClientAuth(clientKP.Private, serverKP.Public)
	d := NewDialer(cfg, ca)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := d.Dial(ctx, "127.0.0.1:1", "example.com")
	if conn != nil {
		conn.Close()
	}
	// We expect a network error (connection refused / timeout).
	// What is NOT acceptable is a nil pointer dereference or missing error.
	if err == nil {
		t.Error("expected connection error for unreachable 127.0.0.1:1, got nil")
	}
}
