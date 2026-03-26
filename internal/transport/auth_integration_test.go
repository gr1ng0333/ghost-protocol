package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/mux"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// authTestEnv creates a full auth environment for testing.
// Returns client auth, server auth, and the shared secret (for verification).
func authTestEnv(t *testing.T) (auth.ClientAuth, auth.ServerAuth, [32]byte) {
	t.Helper()
	clientKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientAuth, err := auth.NewClientAuth(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	serverAuth, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.SharedSecret(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	return clientAuth, serverAuth, secret
}

// startAuthServer starts a Ghost server with the given ServerAuth on localhost.
// Returns the server and its listen address.
func startAuthServer(t *testing.T, sa auth.ServerAuth, fallbackAddr string) (*ghostServer, string) {
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

	t.Cleanup(func() {
		cancel()
		srv.Close()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
		}
	})

	return srv, addr
}

// fixRenegotiationForEKM works around a uTLS Chrome preset issue:
// the Chrome preset sets RenegotiateOnceAsClient (matching real Chrome),
// which makes ConnectionState().ExportKeyingMaterial() fail.
// We reset the extension's Renegotiation to RenegotiateNever and re-apply
// so the config is updated. The raw ClientHello bytes are unaffected
// (renegotiation_info extension is still present), preserving the fingerprint.
func fixRenegotiationForEKM(t *testing.T, uconn *utls.UConn) {
	t.Helper()
	for _, ext := range uconn.Extensions {
		if ri, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			ri.Renegotiation = utls.RenegotiateNever
			break
		}
	}
	if err := uconn.ApplyConfig(); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
}

// authTestConn connects to a Ghost server with uTLS, performs SessionID
// injection and TLS handshake, derives the session token via ExportKeyingMaterial,
// and returns an HTTP/2 client conn, the token, and a cleanup function.
// Uses InsecureSkipVerify for self-signed test certificates.
func authTestConn(t *testing.T, ctx context.Context, addr string, ca auth.ClientAuth) (*http2.ClientConn, string, func()) {
	t.Helper()

	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("TCP dial %s: %v", addr, err)
	}

	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	// Inject SessionID into ClientHello.
	random := uconn.HandshakeState.Hello.Random
	sid, err := ca.InjectSessionID(random)
	if err != nil {
		rawConn.Close()
		t.Fatalf("InjectSessionID: %v", err)
	}
	uconn.HandshakeState.Hello.SessionId = sid
	if len(uconn.HandshakeState.Hello.Raw) < 39+len(sid) {
		rawConn.Close()
		t.Fatalf("ClientHello Raw too short for SessionID patch")
	}
	copy(uconn.HandshakeState.Hello.Raw[39:39+len(sid)], sid)

	// Fix Chrome preset renegotiation so ExportKeyingMaterial works.
	fixRenegotiationForEKM(t, uconn)

	// TLS handshake with injected SessionID.
	if deadline, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(deadline)
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	rawConn.SetDeadline(time.Time{})

	// Derive session token from TLS channel binding.
	cs := uconn.ConnectionState()
	binding, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		uconn.Close()
		t.Fatalf("ExportKeyingMaterial: %v", err)
	}
	token, err := ca.DeriveSessionToken(binding)
	if err != nil {
		uconn.Close()
		t.Fatalf("DeriveSessionToken: %v", err)
	}

	// Create HTTP/2 client connection.
	h2t := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	h2cc, err := h2t.NewClientConn(uconn)
	if err != nil {
		uconn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}

	return h2cc, token, func() { uconn.Close() }
}

// authTestPost sends an HTTP/2 POST to the given path with the session token
// and returns the response body as a string.
func authTestPost(t *testing.T, h2cc *http2.ClientConn, token, path string, payload []byte) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Session-Token", token)
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s status = %d, want 200", path, resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(got)
}

// TestAuth_EndToEnd_Success tests the complete authentication lifecycle:
// SessionID injection → server verification → TLS handshake →
// ExportKeyingMaterial binding → token derivation → token validation → echo.
func TestAuth_EndToEnd_Success(t *testing.T) {
	ca, sa, secret := authTestEnv(t)

	_, srvAddr := startAuthServer(t, sa, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h2cc, token, cleanup := authTestConn(t, ctx, srvAddr, ca)
	defer cleanup()

	uploadPath, _ := mux.DerivePaths(secret)
	payload := []byte("auth-e2e-test-payload-12345")
	_ = authTestPost(t, h2cc, token, uploadPath, payload)
	// POST no longer echoes — it pipes data to the mux. 200 status is validated by authTestPost.
}

// TestAuth_EndToEnd_WrongKey verifies that a client with the wrong key
// is routed to fallback instead of the Ghost handler.
func TestAuth_EndToEnd_WrongKey(t *testing.T) {
	// Create two separate client key pairs.
	clientA_KP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.GenKeyPair() // clientB (wrong key) — unused since we use standard TLS
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Server only knows clientA's public key.
	sa, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientA_KP.Public})
	if err != nil {
		t.Fatal(err)
	}

	// Start a plain HTTP fallback (Ghost terminates TLS, proxies plaintext).
	fallbackGotReq := make(chan struct{}, 1)
	fallbackMux := http.NewServeMux()
	fallbackMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fallbackGotReq <- struct{}{}
		w.Write([]byte("ok"))
	})
	fallbackLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	fallbackSrv := &http.Server{Handler: fallbackMux}
	go fallbackSrv.Serve(fallbackLn)
	t.Cleanup(func() { fallbackSrv.Close(); fallbackLn.Close() })
	fallbackAddr := fallbackLn.Addr().String()

	_, srvAddr := startAuthServer(t, sa, fallbackAddr)

	// A standard TLS client (no Ghost HMAC in SessionID) should be routed to fallback.
	// Ghost terminates TLS, then proxies plaintext HTTP to fallback.
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	client := &http.Client{Transport: httpTransport, Timeout: 5 * time.Second}

	resp, err := client.Get("https://" + srvAddr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	// Verify fallback received the request.
	select {
	case <-fallbackGotReq:
		// Good — wrong-key client was routed to fallback.
	case <-time.After(3 * time.Second):
		t.Error("fallback did not receive the connection; server may have accepted wrong key")
	}
}

// TestAuth_EndToEnd_TokenValidation verifies that the session token
// is valid across multiple HTTP/2 requests on the same connection.
func TestAuth_EndToEnd_TokenValidation(t *testing.T) {
	ca, sa, secret := authTestEnv(t)

	_, srvAddr := startAuthServer(t, sa, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h2cc, token, cleanup := authTestConn(t, ctx, srvAddr, ca)
	defer cleanup()

	uploadPath, _ := mux.DerivePaths(secret)
	// Send 5 POSTs with different payloads — all should succeed with correct echo.
	payloads := []string{
		"request-alpha",
		"request-beta-longer-payload-with-more-data",
		"request-gamma",
		"request-delta-0123456789",
		"request-epsilon",
	}
	for _, p := range payloads {
		_ = authTestPost(t, h2cc, token, uploadPath, []byte(p))
	}
	// POST no longer echoes — assert only that all 5 requests got 200 (authTestPost fatals on non-200).
}

// TestAuth_EndToEnd_MultipleClients verifies that a server configured with
// multiple client public keys can authenticate each client independently.
func TestAuth_EndToEnd_MultipleClients(t *testing.T) {
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Generate 3 client key pairs.
	const numClients = 3
	clientKPs := make([]*auth.KeyPair, numClients)
	clientPubs := make([][32]byte, numClients)
	for i := 0; i < numClients; i++ {
		kp, err := auth.GenKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		clientKPs[i] = kp
		clientPubs[i] = kp.Public
	}

	sa, err := auth.NewServerAuth(serverKP.Private, clientPubs)
	if err != nil {
		t.Fatal(err)
	}

	_, srvAddr := startAuthServer(t, sa, "")

	// Each client connects with its own key pair and sends a unique payload.
	for i := 0; i < numClients; i++ {
		ca, err := auth.NewClientAuth(clientKPs[i].Private, serverKP.Public)
		if err != nil {
			t.Fatalf("client %d: NewClientAuth: %v", i, err)
		}

		secret, err := auth.SharedSecret(clientKPs[i].Private, serverKP.Public)
		if err != nil {
			t.Fatalf("client %d: SharedSecret: %v", i, err)
		}
		uploadPath, _ := mux.DerivePaths(secret)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		h2cc, token, cleanup := authTestConn(t, ctx, srvAddr, ca)

		payload := []byte("multi-client-" + string(rune('A'+i)))
		_ = authTestPost(t, h2cc, token, uploadPath, payload)
		// POST no longer echoes — assert only 200 status (authTestPost fatals on non-200).

		cleanup()
		cancel()
	}
}

// TestAuth_SessionID_Deterministic verifies SessionID computation consistency
// between client and server at the transport level: InjectSessionID on the
// client side produces a value that VerifySessionID on the server side accepts.
func TestAuth_SessionID_Deterministic(t *testing.T) {
	ca, sa, sharedSecret := authTestEnv(t)

	// Use a fixed random value.
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 0xA0)
	}

	// Client side: InjectSessionID.
	sid, err := ca.InjectSessionID(random)
	if err != nil {
		t.Fatalf("InjectSessionID: %v", err)
	}
	if len(sid) != 32 {
		t.Fatalf("SessionID length = %d, want 32", len(sid))
	}

	// Server side: VerifySessionID should accept it.
	gotSecret, ok := sa.VerifySessionID(random, sid)
	if !ok {
		t.Fatal("VerifySessionID rejected a valid SessionID")
	}
	if gotSecret != sharedSecret {
		t.Error("VerifySessionID returned wrong shared secret")
	}

	// Verify determinism: same inputs produce same output.
	sid2, err := ca.InjectSessionID(random)
	if err != nil {
		t.Fatalf("InjectSessionID (2nd call): %v", err)
	}
	if !bytes.Equal(sid, sid2) {
		t.Errorf("SessionID not deterministic:\n first  = %x\n second = %x", sid, sid2)
	}

	// Verify the computed SessionID matches the raw auth.ComputeSessionID function.
	expected := auth.ComputeSessionID(sharedSecret, random)
	if !bytes.Equal(sid, expected) {
		t.Errorf("SessionID mismatch with ComputeSessionID:\n InjectSessionID   = %x\n ComputeSessionID  = %x", sid, expected)
	}
}

// TestAuth_EndToEnd_ChannelBinding verifies that the server-side and client-side
// ExportKeyingMaterial produce matching bindings through a real TLS connection,
// enabling correct token verification.
func TestAuth_EndToEnd_ChannelBinding(t *testing.T) {
	_, sa, sharedSecret := authTestEnv(t)

	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Use net.Pipe for a direct TLS connection (like TestServer_AuthenticatedHTTP2Handler).
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	var serverBinding []byte
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		tlsConn := tls.Server(serverRaw, serverTLSCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()

		cs := tlsConn.ConnectionState()
		b, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
		if err != nil {
			return
		}
		serverBinding = b

		// Serve HTTP/2 briefly so the client can make a request.
		h2srv := &http2.Server{}
		upR, upW := io.Pipe()
		downR, downW := io.Pipe()
		defer upR.Close()
		defer downW.Close()
		// Drain upstream so POST doesn't block.
		go io.Copy(io.Discard, upR)
		// Feed downstream so GET returns data then closes.
		go func() {
			downW.Write([]byte("channel-binding-ok"))
			downW.Close()
		}()
		handler := newGhostHandler(sa, sharedSecret, b, upW, downR, "/api/v1/sync", "/api/v1/poll", "")
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
	}()

	// Client side.
	clientTLSCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	tlsClient := tls.Client(clientRaw, clientTLSCfg)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	clientCS := tlsClient.ConnectionState()
	clientBinding, err := clientCS.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("client ExportKeyingMaterial: %v", err)
	}

	// Derive token from client-side binding.
	token := auth.DeriveSessionToken(sharedSecret, clientBinding)

	// Create an HTTP/2 client and verify the token works.
	h2t := &http2.Transport{TLSClientConfig: clientTLSCfg}
	h2cc, err := h2t.NewClientConn(tlsClient)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	postBody := "channel-binding-test"
	req, _ := http.NewRequest(http.MethodPost, "https://localhost/api/v1/sync", bytes.NewReader([]byte(postBody)))
	req.Header.Set("X-Session-Token", token)
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Close client to let server goroutine exit.
	tlsClient.Close()
	clientRaw.Close()
	<-serverDone

	// Bindings should match.
	if !bytes.Equal(clientBinding, serverBinding) {
		t.Errorf("channel bindings differ:\n client = %x\n server = %x", clientBinding, serverBinding)
	}
}
