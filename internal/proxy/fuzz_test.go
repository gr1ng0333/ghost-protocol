package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fuzzConn is a minimal net.Conn backed by a bytes.Reader for reads
// and io.Discard for writes. Used to feed arbitrary data to SOCKS5 handlers.
type fuzzConn struct {
	r io.Reader
}

func (c *fuzzConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *fuzzConn) Write(p []byte) (int, error)        { return io.Discard.Write(p) }
func (c *fuzzConn) Close() error                       { return nil }
func (c *fuzzConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080} }
func (c *fuzzConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999} }
func (c *fuzzConn) SetDeadline(t time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(t time.Time) error { return nil }

// FuzzSOCKS5Handshake feeds arbitrary bytes into the SOCKS5 Handshake method.
// Any panic is a crash/DoS vulnerability — errors are expected and fine.
func FuzzSOCKS5Handshake(f *testing.F) {
	// Seed 1: valid SOCKS5 method selection (no auth)
	f.Add([]byte{0x05, 0x01, 0x00})

	// Seed 2: two methods offered (no-auth + username/password)
	f.Add([]byte{0x05, 0x02, 0x00, 0x02})

	// Seed 3: wrong version
	f.Add([]byte{0x04, 0x01, 0x00})

	// Seed 4: zero methods
	f.Add([]byte{0x05, 0x00})

	// Seed 5: empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		sc := &socks5Conn{conn: &fuzzConn{r: bytes.NewReader(data)}}
		sc.Handshake() //nolint:errcheck // errors are fine, panics are not
	})
}

// FuzzSOCKS5ReadRequest feeds arbitrary bytes into the SOCKS5 ReadRequest method.
// Any panic is a crash/DoS vulnerability.
func FuzzSOCKS5ReadRequest(f *testing.F) {
	// Seed 1: valid CONNECT to IPv4 127.0.0.1:80
	f.Add([]byte{0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50})

	// Seed 2: valid CONNECT to domain "example.com":443
	f.Add(append(
		[]byte{0x05, 0x01, 0x00, 0x03, 0x0b},
		append([]byte("example.com"), 0x01, 0xBB)...,
	))

	// Seed 3: valid CONNECT to IPv6 [::1]:8080
	f.Add([]byte{
		0x05, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x1F, 0x90,
	})

	// Seed 4: unsupported command (BIND)
	f.Add([]byte{0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50})

	// Seed 5: empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		sc := &socks5Conn{conn: &fuzzConn{r: bytes.NewReader(data)}}
		sc.ReadRequest() //nolint:errcheck // errors are fine, panics are not
	})
}
