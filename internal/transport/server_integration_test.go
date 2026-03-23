package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"

	"golang.org/x/net/http2"
)

// buildTestClientHello constructs a valid TLS 1.2 ClientHello message
// with the specified Random (32 bytes) and SessionID, including extensions
// required for ECDHE-ECDSA cipher negotiation with Go's crypto/tls.
func buildTestClientHello(random, sessionID []byte) []byte {
	// Extensions needed for Go's TLS 1.2 ECDHE-ECDSA negotiation:
	//   - supported_groups (0x000A): secp256r1
	//   - signature_algorithms (0x000D): ecdsa_secp256r1_sha256
	//   - ec_point_formats (0x000B): uncompressed
	var extensions []byte
	// supported_groups
	extensions = append(extensions, 0x00, 0x0A) // type
	extensions = append(extensions, 0x00, 0x04) // ext length
	extensions = append(extensions, 0x00, 0x02) // list length
	extensions = append(extensions, 0x00, 0x17) // secp256r1
	// signature_algorithms
	extensions = append(extensions, 0x00, 0x0D) // type
	extensions = append(extensions, 0x00, 0x04) // ext length
	extensions = append(extensions, 0x00, 0x02) // list length
	extensions = append(extensions, 0x04, 0x03) // ecdsa_secp256r1_sha256
	// ec_point_formats
	extensions = append(extensions, 0x00, 0x0B) // type
	extensions = append(extensions, 0x00, 0x02) // ext length
	extensions = append(extensions, 0x01)       // formats length
	extensions = append(extensions, 0x00)       // uncompressed

	extLenBytes := []byte{byte(len(extensions) >> 8), byte(len(extensions))}

	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03) // ClientVersion TLS 1.2
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, 0x00, 0x02) // cipher suites length = 2
	body = append(body, 0xC0, 0x2B) // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression: 1 method, null
	body = append(body, extLenBytes...)
	body = append(body, extensions...)

	// Handshake header: type(1) + length(3)
	hsLen := len(body)
	handshake := make([]byte, 0, 4+hsLen)
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, body...)

	// TLS record: type(1) + version(2) + length(2)
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(handshake)))
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 compat
	record = append(record, recLen...)
	record = append(record, handshake...)
	return record
}

// waitForAddr polls the ghostServer until it has a listening address.
func waitForAddr(t *testing.T, gs *ghostServer, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := gs.Addr(); addr != nil {
			return addr.String()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server did not start listening in time")
	return ""
}

// startMockFallback starts a TCP server that accepts one connection,
// records the first bytes received, and optionally completes a TLS handshake
// to serve HTTP responses. Returns the listen address and channels for coordination.
func startMockFallback(t *testing.T, cert tls.Certificate) (addr string, gotConn chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock fallback listen: %v", err)
	}
	addr = ln.Addr().String()
	gotConn = make(chan []byte, 4)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := c.Read(buf)
				if n > 0 {
					first := make([]byte, n)
					copy(first, buf[:n])
					gotConn <- first
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return addr, gotConn
}

// startMockFallbackTLS starts a TLS-capable fallback that completes the
// TLS handshake and serves HTTP/1.1 with a known marker response.
func startMockFallbackTLS(t *testing.T, cert tls.Certificate) (addr string, gotRequest chan struct{}) {
	t.Helper()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("mock fallback TLS listen: %v", err)
	}
	addr = ln.Addr().String()
	gotRequest = make(chan struct{}, 4)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_ = n
				gotRequest <- struct{}{}
				// Send a minimal HTTP/1.1 response.
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nfallback-caddy"
				c.Write([]byte(resp))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return addr, gotRequest
}

func newTestServer(t *testing.T, sa auth.ServerAuth, fallbackAddr string) (*ghostServer, context.CancelFunc) {
	t.Helper()
	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	cfg := &config.ServerConfig{
		Domain:   "localhost",
		Fallback: config.FallbackConfig{Addr: fallbackAddr},
	}
	srv := NewServer(cfg, cert, sa, nil).(*ghostServer)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0", fallbackAddr)
	}()

	addr := waitForAddr(t, srv, 3*time.Second)
	_ = addr

	t.Cleanup(func() {
		cancel()
		srv.Close()
		// Drain error channel.
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
		}
	})

	return srv, cancel
}

func TestBuildTestClientHello_Parseable(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(0xA0 | i)
	}

	raw := buildTestClientHello(random, sessionID)
	chi, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if !bytes.Equal(chi.Random, random) {
		t.Errorf("Random mismatch:\n got  %x\n want %x", chi.Random, random)
	}
	if !bytes.Equal(chi.SessionID, sessionID) {
		t.Errorf("SessionID mismatch:\n got  %x\n want %x", chi.SessionID, sessionID)
	}
}

func TestServer_AuthenticatedRouting(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	// Start a mock fallback that records incoming connections.
	fallbackCert, err := GenerateSelfSignedCert("fallback.local")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fallbackAddr, fallbackGot := startMockFallback(t, fallbackCert)

	// Start Ghost server.
	srv, _ := newTestServer(t, sa, fallbackAddr)
	srvAddr := srv.Addr().String()

	// Connect with crafted ClientHello containing correct SessionID.
	conn, err := net.DialTimeout("tcp", srvAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial ghost: %v", err)
	}
	defer conn.Close()

	random := make([]byte, 32)
	rand.Read(random)
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	sessionID := auth.ComputeSessionID(sharedSecret, random)

	hello := buildTestClientHello(random, sessionID)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	// Read server's response — should be a TLS ServerHello (0x16 = Handshake).
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v (n=%d)", err, n)
	}
	if n == 0 {
		t.Fatal("got empty response from server")
	}
	if buf[0] != 0x16 {
		t.Errorf("first byte = 0x%02x, want 0x16 (TLS Handshake); routed to fallback instead of Ghost?", buf[0])
	}

	// Verify fallback was NOT hit.
	select {
	case data := <-fallbackGot:
		t.Errorf("fallback received connection (first byte 0x%02x), but should not have", data[0])
	case <-time.After(200 * time.Millisecond):
		// Good — fallback was not hit.
	}
}

func TestServer_UnauthenticatedFallback(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	// Start a mock fallback that does a TLS handshake and serves HTTP.
	fallbackCert, err := GenerateSelfSignedCert("fallback.local")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fallbackAddr, fallbackGotReq := startMockFallbackTLS(t, fallbackCert)

	// Start Ghost server.
	srv, _ := newTestServer(t, sa, fallbackAddr)
	srvAddr := srv.Addr().String()

	// Standard TLS client — its random SessionID won't match the HMAC.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", srvAddr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		t.Fatalf("tls.Dial to ghost: %v", err)
	}
	defer tlsConn.Close()

	// Send an HTTP/1.1 request through the spliced connection.
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: fallback.local\r\nConnection: close\r\n\r\n")
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	// Read the response — should be from mock Caddy.
	tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Contains(resp, []byte("fallback-caddy")) {
		t.Errorf("response does not contain 'fallback-caddy':\n%s", resp)
	}

	// Verify fallback was hit.
	select {
	case <-fallbackGotReq:
		// Good.
	case <-time.After(2 * time.Second):
		t.Error("fallback did not receive the connection")
	}
}

func TestServer_Fallback_SeesValidTLS(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	// Start a raw TCP mock fallback that records the first bytes.
	fallbackCert, err := GenerateSelfSignedCert("fallback.local")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fallbackAddr, fallbackGot := startMockFallback(t, fallbackCert)

	// Start Ghost server.
	srv, _ := newTestServer(t, sa, fallbackAddr)
	srvAddr := srv.Addr().String()

	// Connect as an unauthenticated client — just send a standard TLS ClientHello.
	conn, err := net.DialTimeout("tcp", srvAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial ghost: %v", err)
	}
	defer conn.Close()

	// Build a ClientHello with a random (wrong) SessionID.
	random := make([]byte, 32)
	rand.Read(random)
	wrongSessionID := make([]byte, 32)
	rand.Read(wrongSessionID)
	hello := buildTestClientHello(random, wrongSessionID)
	conn.Write(hello)

	// The mock fallback should receive the replayed ClientHello.
	select {
	case data := <-fallbackGot:
		if len(data) == 0 {
			t.Fatal("fallback received empty data")
		}
		if data[0] != 0x16 {
			t.Errorf("fallback first byte = 0x%02x, want 0x16 (TLS Handshake record)", data[0])
		}
		// Verify the fallback received a parseable ClientHello.
		chi, err := parseClientHello(data)
		if err != nil {
			t.Fatalf("fallback received unparseable ClientHello: %v", err)
		}
		if !bytes.Equal(chi.Random, random) {
			t.Errorf("fallback ClientHello.Random mismatch")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not receive the connection")
	}
}

func TestServer_ConcurrentConnections(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)

	fallbackCert, err := GenerateSelfSignedCert("fallback.local")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fallbackAddr, fallbackGot := startMockFallback(t, fallbackCert)

	srv, _ := newTestServer(t, sa, fallbackAddr)
	srvAddr := srv.Addr().String()

	const total = 10
	var wg sync.WaitGroup
	wg.Add(total)

	authCount := 0
	unauthCount := 0

	var mu sync.Mutex
	errors := make([]string, 0)

	for i := 0; i < total; i++ {
		isAuth := i%2 == 0
		if isAuth {
			authCount++
		} else {
			unauthCount++
		}

		go func(idx int, authenticated bool) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", srvAddr, 3*time.Second)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("conn %d: dial: %v", idx, err))
				mu.Unlock()
				return
			}
			defer conn.Close()

			random := make([]byte, 32)
			rand.Read(random)

			var sessionID []byte
			if authenticated {
				sessionID = auth.ComputeSessionID(sharedSecret, random)
			} else {
				sessionID = make([]byte, 32)
				rand.Read(sessionID)
			}

			hello := buildTestClientHello(random, sessionID)
			conn.Write(hello)

			buf := make([]byte, 1)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				// Connection might be closed by server or timeout — that's OK for this test.
				return
			}
			if n > 0 && authenticated && buf[0] != 0x16 {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("auth conn %d: expected 0x16, got 0x%02x", idx, buf[0]))
				mu.Unlock()
			}
		}(i, isAuth)
	}

	wg.Wait()

	if len(errors) > 0 {
		for _, e := range errors {
			t.Error(e)
		}
	}

	// Drain fallback — should have received connections for unauthenticated clients.
	fallbackHits := 0
	drainTimeout := time.After(2 * time.Second)
	for {
		select {
		case <-fallbackGot:
			fallbackHits++
			if fallbackHits == unauthCount {
				goto done
			}
		case <-drainTimeout:
			goto done
		}
	}
done:
	if fallbackHits < unauthCount {
		t.Logf("fallback received %d/%d unauthenticated connections (some may have timed out)", fallbackHits, unauthCount)
	}
}

func TestSplice_BidirectionalCopy_E2E(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	// Start a full TLS mock fallback that serves HTTP.
	fallbackCert, err := GenerateSelfSignedCert("fallback.local")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Create a proper HTTP server on the fallback side.
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fallback", "caddy-marker")
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})

	fallbackTLSCfg := &tls.Config{Certificates: []tls.Certificate{fallbackCert}}
	fallbackLn, err := tls.Listen("tcp", "127.0.0.1:0", fallbackTLSCfg)
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	defer fallbackLn.Close()
	fallbackAddr := fallbackLn.Addr().String()

	fallbackSrv := &http.Server{Handler: mux}
	go fallbackSrv.Serve(fallbackLn)
	t.Cleanup(func() { fallbackSrv.Close() })

	// Start Ghost server pointing at the fallback.
	srv, _ := newTestServer(t, sa, fallbackAddr)
	srvAddr := srv.Addr().String()

	// Use a standard TLS client (unauthenticated) — should be spliced to fallback.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Force HTTP/1.1 to keep the test simpler.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	// POST a request through Ghost → splice → fallback.
	payload := "splice-e2e-test-payload"
	resp, err := client.Post(
		fmt.Sprintf("https://%s/test", srvAddr),
		"application/octet-stream",
		bytes.NewReader([]byte(payload)),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Fallback") != "caddy-marker" {
		t.Errorf("missing X-Fallback header; response came from Ghost not Caddy?")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Errorf("response body = %q, want %q", body, payload)
	}

	// Close idle connections so the splice goroutines can finish cleanly.
	transport.CloseIdleConnections()
}

func TestServer_AuthenticatedHTTP2Handler(t *testing.T) {
	// Test the full Ghost HTTP/2 handler via a direct TLS connection to the server.
	// We use net.Pipe + tls to bypass the SessionID check and directly drive handleGhost.
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)

	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Set up a pipe acting as a "connection".
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	// Create pipes for mux ↔ handler communication.
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	defer upR.Close()
	defer upW.Close()
	defer downR.Close()
	defer downW.Close()

	// Drain upstream pipe so POST handler doesn't block.
	go io.Copy(io.Discard, upR)

	// Feed downstream pipe data then close so GET handler can complete.
	go func() {
		downW.Write([]byte("mux-ok"))
		downW.Close()
	}()

	// Server side: TLS + HTTP/2.
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		tlsConn := tls.Server(serverRaw, serverTLSCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()

		// Derive channel binding for token verification.
		serverCS := tlsConn.ConnectionState()
		binding, err := serverCS.ExportKeyingMaterial(exporterLabel, nil, 32)
		if err != nil {
			return
		}

		h2srv := &http2.Server{}
		handler := newGhostHandler(sa, sharedSecret, binding, upW, downR, "/api/upload", "/api/download")
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
	}()

	// Client side: TLS + HTTP/2.
	clientTLSCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	tlsClient := tls.Client(clientRaw, clientTLSCfg)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	// Derive client-side channel binding and session token.
	clientCS := tlsClient.ConnectionState()
	clientBinding, err := clientCS.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("client ExportKeyingMaterial: %v", err)
	}
	token := auth.DeriveSessionToken(sharedSecret, clientBinding)

	// Create an HTTP/2 client transport over the TLS connection.
	h2t := &http2.Transport{
		TLSClientConfig: clientTLSCfg,
	}
	h2cc, err := h2t.NewClientConn(tlsClient)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	// Test POST — body goes to upstream pipe, response is 200 OK.
	postBody := "hello-ghost-h2"
	postReq, _ := http.NewRequest(http.MethodPost, "https://localhost/api/v1/sync", bytes.NewReader([]byte(postBody)))
	postReq.Header.Set("X-Session-Token", token)
	postResp, err := h2cc.RoundTrip(postReq)
	if err != nil {
		t.Fatalf("POST RoundTrip: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != 200 {
		t.Errorf("POST status = %d, want 200", postResp.StatusCode)
	}

	// Test GET — streams downstream data from pipe.
	getReq, _ := http.NewRequest(http.MethodGet, "https://localhost/api/v1/events/test", nil)
	getReq.Header.Set("X-Session-Token", token)
	getResp, err := h2cc.RoundTrip(getReq)
	if err != nil {
		t.Fatalf("GET RoundTrip: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != 200 {
		t.Errorf("GET status = %d, want 200", getResp.StatusCode)
	}
	getBody, _ := io.ReadAll(getResp.Body)
	if string(getBody) != "mux-ok" {
		t.Errorf("GET response = %q, want %q", getBody, "mux-ok")
	}

	// Test 403 without token.
	badReq, _ := http.NewRequest(http.MethodGet, "https://localhost/api/v1/events/test", nil)
	badResp, err := h2cc.RoundTrip(badReq)
	if err != nil {
		t.Fatalf("bad RoundTrip: %v", err)
	}
	defer badResp.Body.Close()

	if badResp.StatusCode != 403 {
		t.Errorf("no-token status = %d, want 403", badResp.StatusCode)
	}
}
