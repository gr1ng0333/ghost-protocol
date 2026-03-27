package transport

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
)

// startEdgeServer starts a Ghost server for edge-case tests.
// Returns the server, its address, the ServerAuth, and a cancel function.
func startEdgeServer(t *testing.T) (*ghostServer, string, auth.ServerAuth) {
	t.Helper()
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.ServerConfig{
		Domain: "localhost",
	}
	srv := NewServer(cfg, cert, sa, nil).(*ghostServer)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0", "")
	}()

	addr := waitForAddr(t, srv, 3*time.Second)

	t.Cleanup(func() {
		cancel()
		srv.Close()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
		}
	})

	return srv, addr, sa
}

func TestServer_MalformedClientHello(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send 32 bytes of random garbage (not a valid TLS record).
	garbage := make([]byte, 32)
	rand.Read(garbage)
	conn.Write(garbage)

	// Server should close connection (parseClientHello will fail).
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Log("server sent unexpected data, but did not crash")
	}
	// Success: no panic, connection closed gracefully.
}

func TestServer_TruncatedClientHello(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send only the first 10 bytes of a valid ClientHello, then close.
	random := make([]byte, 32)
	hello := buildClientHello(random, nil)
	if len(hello) > 10 {
		hello = hello[:10]
	}
	conn.Write(hello)
	conn.Close()

	// Success: server should handle gracefully without hanging.
}

func TestServer_ValidTLS_WrongKey(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a valid ClientHello with a random SessionID (not a valid auth token).
	random := make([]byte, 32)
	rand.Read(random)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	hello := buildClientHello(random, sessionID)
	conn.Write(hello)

	// Server should classify as non-Ghost → route to fallback.
	// Since fallback is empty, the connection gets closed.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadAll(conn)
	// Any outcome is fine (EOF, timeout, data) — just verify no panic.
	_ = err
}

func TestServer_ConcurrentConnectionsEdge(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	const n = 10
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			random := make([]byte, 32)
			rand.Read(random)
			sessionID := make([]byte, 32)
			rand.Read(sessionID)
			hello := buildClientHello(random, sessionID)
			conn.Write(hello)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadAll(conn)
		}()
	}

	wg.Wait()
}

func TestServer_ConnectionFloodEdge(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	goroutinesBefore := runtime.NumGoroutine()

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			// Send garbage then close immediately.
			garbage := make([]byte, 16)
			rand.Read(garbage)
			conn.Write(garbage)
			conn.Close()
		}()
	}
	wg.Wait()

	// Let server goroutines settle.
	time.Sleep(2 * time.Second)

	goroutinesAfter := runtime.NumGoroutine()
	delta := goroutinesAfter - goroutinesBefore
	if delta > 20 {
		t.Errorf("goroutine leak: before=%d after=%d delta=%d", goroutinesBefore, goroutinesAfter, delta)
	}
}

func TestServer_SlowlorisStyle(t *testing.T) {
	t.Parallel()
	_, addr, _ := startEdgeServer(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send TLS ClientHello one byte at a time with delays.
	random := make([]byte, 32)
	hello := buildClientHello(random, nil)

	for i, b := range hello {
		_, err := conn.Write([]byte{b})
		if err != nil {
			// Server may have closed the connection early — that's acceptable.
			t.Logf("write stopped at byte %d: %v", i, err)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	// After sending the complete hello, server should process it.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(conn)
	_ = err // any outcome is fine — no panic is the pass criteria
}
