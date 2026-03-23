package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/mux"
	"ghost/internal/transport"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// testExporterLabel matches the unexported exporterLabel in transport.
const testExporterLabel = "EXPORTER-ghost-session"

// integConn implements mux.PipelineConn using standard Go HTTP/2.
type integConn struct {
	h2cc    *http2.ClientConn
	rawConn net.Conn
	baseURL string
	token   string
}

func (c *integConn) Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error) {
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

func (c *integConn) Recv(ctx context.Context, path string) (io.ReadCloser, error) {
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

func (c *integConn) Close() error { return c.rawConn.Close() }

// integDialGhost connects to a Ghost server using uTLS, performs auth,
// and returns a connection suitable for mux.NewClientPipeline.
func integDialGhost(ctx context.Context, addr string, ca auth.ClientAuth) (*integConn, error) {
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}

	random := uconn.HandshakeState.Hello.Random
	sid, err := ca.InjectSessionID(random)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	uconn.HandshakeState.Hello.SessionId = sid
	if len(uconn.HandshakeState.Hello.Raw) < 39+len(sid) {
		rawConn.Close()
		return nil, err
	}
	copy(uconn.HandshakeState.Hello.Raw[39:39+len(sid)], sid)

	for _, ext := range uconn.Extensions {
		if ri, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			ri.Renegotiation = utls.RenegotiateNever
			break
		}
	}
	if err := uconn.ApplyConfig(); err != nil {
		rawConn.Close()
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(deadline)
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	rawConn.SetDeadline(time.Time{})

	cs := uconn.ConnectionState()
	binding, err := cs.ExportKeyingMaterial(testExporterLabel, nil, 32)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	token, err := ca.DeriveSessionToken(binding)
	if err != nil {
		uconn.Close()
		return nil, err
	}

	h2t := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	h2cc, err := h2t.NewClientConn(uconn)
	if err != nil {
		uconn.Close()
		return nil, err
	}

	return &integConn{
		h2cc:    h2cc,
		rawConn: uconn,
		baseURL: "https://localhost",
		token:   token,
	}, nil
}

// freeAddr returns a free TCP address by listening then closing.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitForTCP polls until a TCP server accepts connections at addr.
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TCP server at %s did not start in time", addr)
}

// splitHostPort splits "host:port" into host string and port uint16.
func integSplitHostPort(t *testing.T, addr string) (string, uint16) {
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

// startEchoServer starts a TCP server that echoes all received data.
func startEchoServer(t *testing.T) string {
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
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startPrefixEchoServer starts a TCP server that echoes with a prefix.
func startPrefixEchoServer(t *testing.T, prefix string) string {
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					reply := append([]byte(prefix), buf[:n]...)
					if _, err := c.Write(reply); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startGhostServer starts a full Ghost server and returns its address.
func startGhostServer(t *testing.T, sa auth.ServerAuth) string {
	t.Helper()
	addr := freeAddr(t)

	cert, err := transport.GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.ServerConfig{
		Domain: "localhost",
	}
	srv := transport.NewServer(cfg, cert, sa, nil)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, addr, "")
	}()

	waitForTCP(t, addr)

	t.Cleanup(func() {
		cancel()
		srv.Close()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
		}
	})

	return addr
}

// setupGhostPipeline creates the full auth, server, and client pipeline.
func setupGhostPipeline(t *testing.T, ctx context.Context) (*mux.ClientPipeline, *integConn) {
	t.Helper()

	clientKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := auth.NewClientAuth(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := auth.SharedSecret(clientKP.Private, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	ghostAddr := startGhostServer(t, sa)

	conn, err := integDialGhost(ctx, ghostAddr, ca)
	if err != nil {
		t.Fatalf("integDialGhost: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	up, down := mux.DerivePaths(sharedSecret)
	pipeline, err := mux.NewClientPipeline(ctx, conn, up, down, nil)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}
	t.Cleanup(func() { pipeline.Close() })

	return pipeline, conn
}

func TestSOCKS5_ThroughGhostTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pipeline, _ := setupGhostPipeline(t, ctx)

	// Start echo server as the destination.
	echoAddr := startEchoServer(t)
	echoHost, echoPort := integSplitHostPort(t, echoAddr)

	// Start SOCKS5 server wired to the Ghost pipeline.
	socks5srv := NewSOCKS5Server().(*socks5Server)
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		return pipeline.Mux.Open(ctx, addr, port)
	}

	socks5Addr := freeAddr(t)
	go socks5srv.ListenAndServe(ctx, socks5Addr, opener)
	waitForTCP(t, socks5Addr)
	t.Cleanup(func() { socks5srv.Close() })

	// Connect through SOCKS5.
	conn, err := net.DialTimeout("tcp", socks5Addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	socks5Connect(t, conn, net.ParseIP(echoHost), echoPort)

	// Send data and verify echo.
	msg := []byte("hello ghost tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestSOCKS5_MultipleSites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pipeline, _ := setupGhostPipeline(t, ctx)

	// Start 3 mock servers with unique prefixes.
	prefixes := []string{"ALPHA:", "BETA:", "GAMMA:"}
	addrs := make([]string, 3)
	for i, p := range prefixes {
		addrs[i] = startPrefixEchoServer(t, p)
	}

	// Start SOCKS5 server.
	socks5srv := NewSOCKS5Server().(*socks5Server)
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		return pipeline.Mux.Open(ctx, addr, port)
	}
	socks5Addr := freeAddr(t)
	go socks5srv.ListenAndServe(ctx, socks5Addr, opener)
	waitForTCP(t, socks5Addr)
	t.Cleanup(func() { socks5srv.Close() })

	// Connect to each mock server through SOCKS5.
	for i, mockAddr := range addrs {
		host, port := integSplitHostPort(t, mockAddr)

		conn, err := net.DialTimeout("tcp", socks5Addr, 3*time.Second)
		if err != nil {
			t.Fatalf("[%d] dial socks5: %v", i, err)
		}
		defer conn.Close()

		socks5Handshake(t, conn)
		socks5Connect(t, conn, net.ParseIP(host), port)

		msg := []byte("test-data")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("[%d] write: %v", i, err)
		}

		want := prefixes[i] + "test-data"
		got := make([]byte, len(want))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("[%d] read: %v", i, err)
		}
		if string(got) != want {
			t.Fatalf("[%d] got %q, want %q", i, got, want)
		}
	}
}

func TestSOCKS5_LargeTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pipeline, _ := setupGhostPipeline(t, ctx)
	echoAddr := startEchoServer(t)
	echoHost, echoPort := integSplitHostPort(t, echoAddr)

	socks5srv := NewSOCKS5Server().(*socks5Server)
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		return pipeline.Mux.Open(ctx, addr, port)
	}
	socks5Addr := freeAddr(t)
	go socks5srv.ListenAndServe(ctx, socks5Addr, opener)
	waitForTCP(t, socks5Addr)
	t.Cleanup(func() { socks5srv.Close() })

	conn, err := net.DialTimeout("tcp", socks5Addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	socks5Connect(t, conn, net.ParseIP(echoHost), echoPort)

	// Generate 1MB of deterministic data.
	const size = 1 << 20 // 1MB
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251) // deterministic pattern
	}
	wantHash := sha256.Sum256(data)

	// Write in a goroutine (may block if pipe fills).
	go func() {
		conn.Write(data)
	}()

	// Read all echoed data.
	received := make([]byte, size)
	conn.SetReadDeadline(time.Now().Add(25 * time.Second))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("read large transfer: %v", err)
	}

	gotHash := sha256.Sum256(received)
	if wantHash != gotHash {
		t.Fatalf("SHA-256 mismatch: sent %x, received %x", wantHash, gotHash)
	}
}
