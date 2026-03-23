package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// mockStream wraps a net.Conn to satisfy the Stream interface for tests.
type mockStream struct {
	net.Conn
	id uint32
}

func (m *mockStream) ID() uint32 { return m.id }

// newMockStreamPair creates two connected mock streams.
func newMockStreamPair(id uint32) (*mockStream, *mockStream) {
	a, b := net.Pipe()
	return &mockStream{Conn: a, id: id}, &mockStream{Conn: b, id: id}
}

// waitForListener polls until the socks5Server listener is set, returns its address.
func waitForListener(t *testing.T, srv *socks5Server) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		ln := srv.listener
		srv.mu.Unlock()
		if ln != nil {
			return ln.Addr().String()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("socks5 listener did not start in time")
	return ""
}

// socks5Handshake performs the client side of a SOCKS5 handshake on conn.
func socks5Handshake(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("handshake reply = %x, want [05 00]", reply)
	}
}

// socks5Connect sends a SOCKS5 CONNECT request for an IPv4 address.
func socks5Connect(t *testing.T, conn net.Conn, ip net.IP, port uint16) {
	t.Helper()
	ip4 := ip.To4()
	if ip4 == nil {
		t.Fatal("socks5Connect requires IPv4")
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip4...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("connect reply rep = 0x%02x, want 0x00", resp[1])
	}
}

// socks5ConnectDomain sends a SOCKS5 CONNECT request for a domain.
func socks5ConnectDomain(t *testing.T, conn net.Conn, domain string, port uint16) {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect domain: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("connect reply rep = 0x%02x, want 0x00", resp[1])
	}
}

// --- Protocol unit tests ---

func TestHandshake_NoAuth(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Client writes method negotiation.
	client.Write([]byte{0x05, 0x01, 0x00})

	// Client reads reply.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Handshake() = %v, want nil", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("reply = %x, want [05 00]", reply)
	}
}

func TestHandshake_UnsupportedMethod(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Only offer username/password (0x02).
	client.Write([]byte{0x05, 0x01, 0x02})

	// Read the rejection reply.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error")
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("reply = %x, want [05 FF]", reply)
	}
}

func TestReadRequest_IPv4(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// VER=0x05, CMD=CONNECT, RSV=0x00, ATYP=IPv4
	// IP: 93.184.216.34, Port: 443 (0x01BB)
	client.Write([]byte{
		0x05, 0x01, 0x00, 0x01,
		93, 184, 216, 34,
		0x01, 0xBB,
	})

	r := <-resCh
	if r.err != nil {
		t.Fatalf("ReadRequest() error = %v", r.err)
	}
	if r.addr != "93.184.216.34" {
		t.Errorf("addr = %q, want %q", r.addr, "93.184.216.34")
	}
	if r.port != 443 {
		t.Errorf("port = %d, want 443", r.port)
	}
}

func TestReadRequest_Domain(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// ATYP=0x03 (domain), length=11, "example.com", port=80 (0x0050)
	req := []byte{0x05, 0x01, 0x00, 0x03, 0x0B}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x00, 0x50)
	client.Write(req)

	r := <-resCh
	if r.err != nil {
		t.Fatalf("ReadRequest() error = %v", r.err)
	}
	if r.addr != "example.com" {
		t.Errorf("addr = %q, want %q", r.addr, "example.com")
	}
	if r.port != 80 {
		t.Errorf("port = %d, want 80", r.port)
	}
}

func TestReadRequest_IPv6(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// ATYP=0x04 (IPv6), ::1, port=443
	ipv6 := make([]byte, 16)
	ipv6[15] = 1 // ::1
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, ipv6...)
	req = append(req, 0x01, 0xBB)
	client.Write(req)

	r := <-resCh
	if r.err != nil {
		t.Fatalf("ReadRequest() error = %v", r.err)
	}
	if r.addr != "::1" {
		t.Errorf("addr = %q, want %q", r.addr, "::1")
	}
	if r.port != 443 {
		t.Errorf("port = %d, want 443", r.port)
	}
}

func TestReadRequest_UnsupportedCmd(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// CMD=0x02 (BIND). ReadRequest checks CMD after reading only the 4-byte
	// header, so the remaining 6 bytes won't be consumed. Write in a goroutine
	// to avoid blocking the main goroutine (net.Pipe is synchronous).
	go func() {
		client.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	// ReadRequest should send a rep=0x07 reply before returning error.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Errorf("reply rep = 0x%02x, want 0x07", reply[1])
	}

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for BIND command")
	}
}

func TestSendReply_Success(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.SendReply(0x00, "0.0.0.0", 0)
	}()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("SendReply() = %v", err)
	}
	want := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = %x, want %x", reply, want)
	}
}

func TestSendReply_Failure(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.SendReply(0x05, "0.0.0.0", 0)
	}()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("SendReply() = %v", err)
	}
	if reply[1] != 0x05 {
		t.Errorf("reply rep = 0x%02x, want 0x05", reply[1])
	}
}

// --- Server tests ---

func TestServer_ConnectAndRelay(t *testing.T) {
	t.Parallel()

	// Channel to receive the remote side of the mock stream.
	remoteCh := make(chan *mockStream, 1)
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		local, remote := newMockStreamPair(1)
		remoteCh <- remote
		return local, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	t.Cleanup(func() { srv.Close() })

	// Connect as SOCKS5 client.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	socks5ConnectDomain(t, conn, "example.com", 443)

	// Get the remote end of the mock stream.
	var remote *mockStream
	select {
	case remote = <-remoteCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for mock stream")
	}
	defer remote.Close()

	// Write data through SOCKS5 → should arrive at remote end of mock stream.
	msg := []byte("hello through socks5")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(remote, buf); err != nil {
		t.Fatalf("read from remote: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("remote got %q, want %q", buf, msg)
	}

	// Write back through mock stream → should arrive at SOCKS5 client.
	reply := []byte("reply from remote")
	if _, err := remote.Write(reply); err != nil {
		t.Fatalf("write to remote: %v", err)
	}

	got := make([]byte, len(reply))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read from socks5: %v", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("socks5 client got %q, want %q", got, reply)
	}
}

func TestServer_TunnelError(t *testing.T) {
	t.Parallel()

	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		return nil, errors.New("tunnel unavailable")
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Handshake.
	conn.Write([]byte{0x05, 0x01, 0x00})
	hsReply := make([]byte, 2)
	io.ReadFull(conn, hsReply)

	// CONNECT request (IPv4 127.0.0.1:80).
	conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})

	// Read reply — should indicate connection refused (0x05).
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] == 0x00 {
		t.Fatal("expected error reply, got success")
	}
	if reply[1] != 0x05 {
		t.Errorf("reply rep = 0x%02x, want 0x05 (connection refused)", reply[1])
	}
}

func TestServer_ConcurrentConnections(t *testing.T) {
	t.Parallel()

	const numConns = 10

	// Per-port channel for mock stream remote ends.
	remoteChs := make(map[uint16]chan *mockStream)
	var chMu sync.Mutex
	for i := 0; i < numConns; i++ {
		port := uint16(9000 + i)
		remoteChs[port] = make(chan *mockStream, 1)
	}

	var nextID uint32
	var idMu sync.Mutex
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		idMu.Lock()
		nextID++
		id := nextID
		idMu.Unlock()
		local, remote := newMockStreamPair(id)
		chMu.Lock()
		ch := remoteChs[port]
		chMu.Unlock()
		if ch != nil {
			ch <- remote
		}
		return local, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	t.Cleanup(func() { srv.Close() })

	var wg sync.WaitGroup
	errs := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()

			// Handshake.
			conn.Write([]byte{0x05, 0x01, 0x00})
			hsReply := make([]byte, 2)
			io.ReadFull(conn, hsReply)

			// CONNECT with unique port.
			port := uint16(9000 + idx)
			domain := "example.com"
			req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
			req = append(req, []byte(domain)...)
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, port)
			req = append(req, portBuf...)
			conn.Write(req)

			reply := make([]byte, 10)
			io.ReadFull(conn, reply)
			if reply[1] != 0x00 {
				errs <- errors.New("connect failed")
				return
			}

			// Get the remote mock stream for this port.
			chMu.Lock()
			ch := remoteChs[port]
			chMu.Unlock()

			var remote *mockStream
			select {
			case remote = <-ch:
			case <-time.After(3 * time.Second):
				errs <- errors.New("timed out waiting for remote")
				return
			}
			defer remote.Close()

			// Send unique data.
			msg := []byte{byte('A' + idx), byte('A' + idx), byte('A' + idx)}
			conn.Write(msg)

			// Read it from remote.
			buf := make([]byte, len(msg))
			remote.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(remote, buf); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(buf, msg) {
				errs <- errors.New("data mismatch at remote")
				return
			}

			// Echo back through remote.
			echoMsg := append([]byte("echo:"), msg...)
			remote.Write(echoMsg)

			got := make([]byte, len(echoMsg))
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, echoMsg) {
				errs <- errors.New("echo mismatch")
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent conn error: %v", err)
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	t.Parallel()

	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		local, _ := newMockStreamPair(1)
		return local, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	}()
	addr := waitForListener(t, srv)

	// Establish a connection to verify the server is working.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	// Close the server.
	srv.Close()

	// ListenAndServe should return nil on clean shutdown.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after Close()")
	}

	// New connections should be refused.
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial to fail after shutdown")
	}
}

// --- Relay tests ---

func TestRelay_BidirectionalData(t *testing.T) {
	t.Parallel()

	a1, a2 := net.Pipe() // a1 ↔ a2
	b1, b2 := net.Pipe() // b1 ↔ b2

	defer a1.Close()
	defer a2.Close()
	defer b1.Close()
	defer b2.Close()

	// relay(a2, b1):
	// io.Copy(a2, b1) — reads from b1, writes to a2 — so b2→b1→a2→a1
	// io.Copy(b1, a2) — reads from a2, writes to b1 — so a1→a2→b1→b2
	go relay(a2, b1)

	// Write "hello" to a1 → relay copies a1→a2→b1→b2 — read from b2.
	go func() {
		a1.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatalf("read from b2: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("b2 got %q, want %q", buf, "hello")
	}

	// Write "world" to b2 → relay copies b2→b1→a2→a1 — read from a1.
	go func() {
		b2.Write([]byte("world"))
	}()

	buf2 := make([]byte, 5)
	if _, err := io.ReadFull(a1, buf2); err != nil {
		t.Fatalf("read from a1: %v", err)
	}
	if string(buf2) != "world" {
		t.Fatalf("a1 got %q, want %q", buf2, "world")
	}
}

func TestRelay_OneSideClose(t *testing.T) {
	t.Parallel()

	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	defer b2.Close()

	done := make(chan struct{})
	go func() {
		relay(a2, b1)
		close(done)
	}()

	// Close one side — relay should eventually close both and return.
	a1.Close()

	select {
	case <-done:
		// relay returned — good.
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after closing one side")
	}
}

// --- Coverage gap tests ---

func TestHandshake_WrongVersion(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Send SOCKS4 version. Handshake reads 2-byte header then returns error
	// without consuming the method byte, so write in a goroutine to avoid
	// blocking on the synchronous pipe.
	go func() {
		client.Write([]byte{0x04, 0x01, 0x00})
	}()

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error for SOCKS4 version")
	}
}

func TestHandshake_ZeroMethods(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// nmethods = 0.
	client.Write([]byte{0x05, 0x00})

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error for zero methods")
	}
}

func TestHandshake_MultipleMethodsPicksNoAuth(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Offer both username/password (0x02) and no-auth (0x00).
	client.Write([]byte{0x05, 0x02, 0x02, 0x00})

	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Handshake() = %v, want nil", err)
	}
	if reply[1] != 0x00 {
		t.Errorf("selected method = 0x%02x, want 0x00", reply[1])
	}
}

func TestHandshake_ReadMethodsError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Send header claiming 3 methods, then close before sending them.
	client.Write([]byte{0x05, 0x03})
	client.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error for read methods failure")
	}
}

func TestReadRequest_WrongVersion(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Send version 0x04. ReadRequest reads only the 4-byte header then
	// returns error, leaving 6 bytes unconsumed. Write in goroutine.
	go func() {
		client.Write([]byte{0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50})
	}()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for wrong SOCKS version")
	}
}

func TestReadRequest_UnknownATYP(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// ATYP=0x02 is invalid.
	go func() {
		client.Write([]byte{0x05, 0x01, 0x00, 0x02})
	}()

	// ReadRequest sends repAddrNotSupported reply before returning error.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != repAddrNotSupported {
		t.Errorf("reply rep = 0x%02x, want 0x%02x", reply[1], repAddrNotSupported)
	}

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for unknown ATYP")
	}
}

func TestReadRequest_ReadHeaderError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Close immediately so ReadRequest gets EOF on header read.
	client.Close()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for read header failure")
	}
}

func TestReadRequest_ReadIPv4Error(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Send valid header with ATYP=IPv4 then close before address bytes.
	client.Write([]byte{0x05, 0x01, 0x00, 0x01})
	client.Close()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for partial IPv4 read")
	}
}

func TestReadRequest_ReadDomainLenError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Send valid header with ATYP=domain then close before domain length byte.
	client.Write([]byte{0x05, 0x01, 0x00, 0x03})
	client.Close()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for domain length read failure")
	}
}

func TestReadRequest_ReadDomainNameError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Send header + domain length=11 then close before full domain.
	client.Write([]byte{0x05, 0x01, 0x00, 0x03, 0x0B})
	client.Write([]byte("exam")) // only 4 of 11 bytes
	client.Close()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for partial domain name read")
	}
}

func TestReadRequest_ReadPortError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()

	sc := &socks5Conn{conn: server}

	type result struct {
		addr string
		port uint16
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		a, p, e := sc.ReadRequest()
		resCh <- result{a, p, e}
	}()

	// Send valid IPv4 request but close before the port bytes.
	client.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1})
	client.Close()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for port read failure")
	}
}

func TestSendReply_WriteError(t *testing.T) {
	t.Parallel()
	_, server := net.Pipe()

	sc := &socks5Conn{conn: server}

	// Close the conn so Write fails.
	server.Close()

	err := sc.SendReply(0x00, "0.0.0.0", 0)
	if err == nil {
		t.Fatal("SendReply() = nil, want error for write to closed conn")
	}
}

func TestServer_RequestFailAfterHandshake(t *testing.T) {
	t.Parallel()

	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		local, _ := newMockStreamPair(1)
		return local, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Do a valid handshake, then close conn so ReadRequest fails.
	socks5Handshake(t, conn)
	conn.Close()

	// Give handleConn time to process the error path.
	time.Sleep(100 * time.Millisecond)
}

func TestClose_NoListener(t *testing.T) {
	t.Parallel()

	srv := &socks5Server{}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	t.Parallel()

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", nil)
	waitForListener(t, srv)

	if err := srv.Close(); err != nil {
		t.Fatalf("first Close() = %v", err)
	}
	// Second close should not error.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
}
