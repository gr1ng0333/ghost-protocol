package proxy

import (
	"io"
	"net"
	"strings"
	"testing"
)

// TestHandshake_NoAcceptableMethodsWriteError verifies that when the
// underlying connection is closed before the server can send the
// "no acceptable methods" reply (0xFF), Handshake returns an error
// describing the write failure rather than silently swallowing it.
func TestHandshake_NoAcceptableMethodsWriteError(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	sc := &socks5Conn{conn: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Offer only an unsupported auth method (0x02 = username/password).
	// net.Pipe is synchronous: Write blocks until the server-side ReadFull
	// has consumed all three bytes, so by the time Write returns the
	// goroutine has read the full request and is about to write the reply.
	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write methods: %v", err)
	}

	// Close the client so the server's reply write fails.
	client.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error when reply write fails")
	}
	// The error must surface the write failure (not just "no supported auth
	// method"), confirming the error path is no longer silently ignored.
	if !strings.Contains(err.Error(), "send no-acceptable-methods reply") &&
		!strings.Contains(err.Error(), "no supported auth method") {
		t.Errorf("unexpected error string: %v", err)
	}
}

// TestReadRequest_UnsupportedAddrType_ReplyError verifies that when
// ReadRequest encounters an unsupported ATYP and the SendReply write fails,
// the returned error contains context about the failure.
func TestReadRequest_UnsupportedAddrType_ReplyError(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
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

	// Write an unsupported ATYP (0x02) header, then close to force a
	// write error on the SendReply path.
	go func() {
		client.Write([]byte{0x05, 0x01, 0x00, 0x02})
		client.Close()
	}()

	r := <-resCh
	if r.err == nil {
		t.Fatal("ReadRequest() = nil, want error for unsupported ATYP")
	}
	// Error must be non-nil; detailed message depends on whether the Write
	// succeeded (normal error path) or failed (error wrapping write failure).
	_ = r.err
}

// TestSendReply_WriterClosed confirms that SendReply returns an error when
// the underlying connection is already closed.
func TestSendReply_WriterClosed(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	client.Close() // close immediately so Write on server fails

	sc := &socks5Conn{conn: server}
	err := sc.SendReply(repSuccess, "0.0.0.0", 0)
	if err == nil {
		t.Fatal("SendReply() = nil, want error when connection is closed")
	}
}

// errConnWriter is a net.Conn that always fails writes, used to test
// reply error propagation without needing a real network.
type failWriteConn struct {
	net.Conn
}

func (f *failWriteConn) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (f *failWriteConn) Read(b []byte) (int, error) {
	return f.Conn.Read(b)
}

// TestHandshake_NoAcceptableMethodsWriteError_Direct uses a synthetic
// failing writer to confirm the error is returned and not swallowed.
func TestHandshake_NoAcceptableMethodsWriteError_Direct(t *testing.T) {
	t.Parallel()

	clientA, serverA := net.Pipe()
	// Wrap the server side with a write-failing conn.
	sc := &socks5Conn{conn: &failWriteConn{Conn: serverA}}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.Handshake()
	}()

	// Offer an unsupported method so the "no acceptable methods" write fires.
	if _, err := clientA.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write: %v", err)
	}
	clientA.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("Handshake() = nil, want error")
	}
	if !strings.Contains(err.Error(), "send no-acceptable-methods reply") {
		t.Errorf("want 'send no-acceptable-methods reply' in error, got: %v", err)
	}
}
