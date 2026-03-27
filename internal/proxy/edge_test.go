package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSOCKS5_DestinationRefused(t *testing.T) {
	t.Parallel()

	// StreamOpener that always returns connection refused.
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		return nil, &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &net.DNSError{Err: "connection refused", IsNotFound: false},
		}
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// Send CONNECT to 127.0.0.1:19999.
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 19999)
	req = append(req, portBuf...)
	conn.Write(req)

	// Read reply — should get a non-success rep byte.
	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] == 0x00 {
		t.Fatal("expected non-success reply for refused connection")
	}
}

func TestSOCKS5_VeryLongDomainName(t *testing.T) {
	t.Parallel()

	// 255-character domain (max for SOCKS5 ATYP_DOMAIN).
	domain := strings.Repeat("a", 255)

	// Use a pipe to test the socks5Conn ReadRequest directly.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sc := &socks5Conn{conn: serverConn}

	go func() {
		// VER=5, CMD=CONNECT, RSV=0, ATYP=domain
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x03, 0xFF})
		clientConn.Write([]byte(domain))
		// Port = 80
		clientConn.Write([]byte{0x00, 0x50})
	}()

	addr, port, err := sc.ReadRequest()
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if addr != domain {
		t.Fatalf("addr length = %d, want %d", len(addr), len(domain))
	}
	if port != 80 {
		t.Fatalf("port = %d, want 80", port)
	}
}

func TestSOCKS5_InvalidAddressType(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sc := &socks5Conn{conn: serverConn}

	go func() {
		// VER=5, CMD=CONNECT, RSV=0, ATYP=0x05 (invalid)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x05})
		// Discard any reply the server sends.
		io.Copy(io.Discard, clientConn)
	}()

	_, _, err := sc.ReadRequest()
	if err == nil {
		t.Fatal("expected error for invalid address type 0x05")
	}
}

func TestSOCKS5_UDPAssociateUnsupported(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sc := &socks5Conn{conn: serverConn}

	// Drain reply in background so SendReply doesn't block on pipe.
	go func() {
		io.Copy(io.Discard, clientConn)
	}()

	// Send 4-byte header: VER=5, CMD=UDP_ASSOCIATE(0x03), RSV=0, ATYP=IPv4.
	// ReadRequest reads exactly 4 bytes then calls SendReply for unsupported CMD.
	go func() {
		clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	}()

	_, _, err := sc.ReadRequest()
	if err == nil {
		t.Fatal("expected error for UDP ASSOCIATE command")
	}
}

func TestSOCKS5_PartialRequest(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	sc := &socks5Conn{conn: serverConn}

	go func() {
		// Send first 3 bytes of a valid SOCKS5 header, then close.
		clientConn.Write([]byte{0x05, 0x01, 0x00})
		clientConn.Close()
	}()

	_, _, err := sc.ReadRequest()
	if err == nil {
		t.Fatal("expected error for partial request")
	}
}

func TestSOCKS5_RapidConnections(t *testing.T) {
	t.Parallel()

	// StreamOpener: create mock stream pairs for each connection.
	var streamMu sync.Mutex
	streamID := uint32(0)
	opener := func(ctx context.Context, addr string, port uint16) (Stream, error) {
		streamMu.Lock()
		streamID++
		id := streamID
		streamMu.Unlock()
		_, remote := newMockStreamPair(id)
		// Close remote side immediately (we just test handshake + connect).
		go func() {
			time.Sleep(100 * time.Millisecond)
			remote.Close()
		}()
		local, _ := newMockStreamPair(id + 1000)
		return local, nil
	}

	srv := NewSOCKS5Server().(*socks5Server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.ListenAndServe(ctx, "127.0.0.1:0", opener)
	addr := waitForListener(t, srv)
	defer srv.Close()

	const n = 100
	var wg sync.WaitGroup
	var successes, failures int64
	var mu sync.Mutex

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// Handshake.
			conn.Write([]byte{0x05, 0x01, 0x00})
			reply := make([]byte, 2)
			if _, err := io.ReadFull(conn, reply); err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}

			// CONNECT to unique port.
			port := uint16(9000 + idx)
			req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, port)
			req = append(req, portBuf...)
			conn.Write(req)

			// Read connect reply.
			resp := make([]byte, 10)
			if _, err := io.ReadFull(conn, resp); err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}

			mu.Lock()
			successes++
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// All should have at least connected (handshake + request).
	// Some failures are acceptable under extreme concurrency, but no panics.
	t.Logf("rapid connections: %d successes, %d failures out of %d", successes, failures, n)
}

func TestSOCKS5_BindUnsupported(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sc := &socks5Conn{conn: serverConn}

	// Drain reply in background so SendReply doesn't block on pipe.
	go func() {
		io.Copy(io.Discard, clientConn)
	}()

	// Send header: VER=5, CMD=BIND(0x02), RSV=0, ATYP=IPv4.
	go func() {
		clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	}()

	_, _, err := sc.ReadRequest()
	if err == nil {
		t.Fatal("expected error for BIND command")
	}
}
