package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"
)

// Conn represents an HTTP/2 connection to the Ghost server.
type Conn interface {
	// Send transmits a payload as an HTTP/2 POST request.
	// path is the API-like endpoint path (e.g., "/api/v1/sync").
	// Returns the response body reader. Caller must close it.
	Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error)

	// Recv opens an HTTP/2 GET request to receive data.
	// path is the endpoint (e.g., "/api/v1/events/{session}").
	// Returns the response body reader. Caller must close it.
	Recv(ctx context.Context, path string) (io.ReadCloser, error)

	// Close terminates the HTTP/2 connection gracefully.
	Close() error

	// Alive reports whether the underlying connection is healthy.
	Alive() bool
}

// Dialer creates new Conn instances.
type Dialer interface {
	// Dial establishes an HTTP/2 connection to the specified server.
	// addr is "host:port". sni is the TLS SNI value.
	Dial(ctx context.Context, addr, sni string) (Conn, error)
}

// h2Conn wraps an http2.ClientConn and its underlying net.Conn.
type h2Conn struct {
	cc      *http2.ClientConn
	rawConn net.Conn
	baseURL string   // "https://{sni}"
	pho     []string // pseudo-header order
}

func (c *h2Conn) Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("transport.Send: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header[http.PHeaderOrderKey] = c.pho

	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("transport.Send: round trip: %w", err)
	}
	return resp.Body, nil
}

func (c *h2Conn) Recv(ctx context.Context, path string) (io.ReadCloser, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("transport.Recv: build request: %w", err)
	}
	req.Header[http.PHeaderOrderKey] = c.pho

	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("transport.Recv: round trip: %w", err)
	}
	return resp.Body, nil
}

func (c *h2Conn) Close() error {
	ccErr := c.cc.Close()
	rawErr := c.rawConn.Close()
	if ccErr != nil {
		return fmt.Errorf("transport.Close: h2: %w", ccErr)
	}
	if rawErr != nil {
		return fmt.Errorf("transport.Close: conn: %w", rawErr)
	}
	return nil
}

func (c *h2Conn) Alive() bool {
	// Attempt a zero-length read with an immediate deadline to probe connection health.
	one := make([]byte, 1)
	if err := c.rawConn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
		return false
	}
	_, err := c.rawConn.Read(one)
	// Reset the deadline so future I/O is unaffected.
	_ = c.rawConn.SetReadDeadline(time.Time{})
	if err == nil {
		// Unexpected data — connection may be in odd state but is alive.
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// Timeout on zero-deadline read means the connection is alive and idle.
		return true
	}
	// Any other error (EOF, connection reset, etc.) means dead.
	return false
}

// h2Dialer implements Dialer using uTLS + fhttp/http2.
type h2Dialer struct {
	cfg     H2Config
	helloID utls.ClientHelloID
}

// NewDialer returns a Dialer configured with the given H2Config.
func NewDialer(cfg H2Config) Dialer {
	return &h2Dialer{
		cfg:     cfg,
		helloID: utls.HelloChrome_Auto,
	}
}

func (d *h2Dialer) Dial(ctx context.Context, addr, sni string) (Conn, error) {
	// 1. Dial TCP with context support.
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport.Dial: TCP %s: %w", addr, err)
	}

	// 2. Perform uTLS handshake.
	uconn := utls.UClient(rawConn, &utls.Config{ServerName: sni}, d.helloID)
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: TLS handshake: %w", err)
	}

	state := uconn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("transport.Dial: expected ALPN h2, got %q", state.NegotiatedProtocol)
	}
	slog.Debug("transport.Dial: TLS handshake complete",
		"addr", addr, "sni", sni, "alpn", state.NegotiatedProtocol,
		"tls_version", fmt.Sprintf("0x%04x", state.Version))

	// 3. Create http2.Transport with Chrome SETTINGS from H2Config.
	h2t := &http2.Transport{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   d.cfg.HeaderTableSize,
			http2.SettingEnablePush:        d.cfg.EnablePush,
			http2.SettingInitialWindowSize: d.cfg.InitialWindowSize,
			http2.SettingMaxHeaderListSize: d.cfg.MaxHeaderListSize,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		ConnectionFlow:    d.cfg.WindowUpdateSize,
		PseudoHeaderOrder: d.cfg.PseudoHeaderOrder,
	}

	// 4. Create HTTP/2 ClientConn on top of the uTLS connection.
	cc, err := h2t.NewClientConn(uconn)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("transport.Dial: h2 client conn: %w", err)
	}
	slog.Debug("transport.Dial: HTTP/2 connection established", "addr", addr, "sni", sni)

	return &h2Conn{
		cc:      cc,
		rawConn: uconn,
		baseURL: "https://" + sni,
		pho:     d.cfg.PseudoHeaderOrder,
	}, nil
}
