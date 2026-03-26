package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"ghost/internal/auth"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"
)

// exporterLabel is the TLS Exported Keying Material label used for channel binding.
const exporterLabel = "EXPORTER-ghost-session"

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
	token   string   // session token for X-Session-Token header
}

func (c *h2Conn) Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("transport.Send: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-Token", c.token)
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
	req.Header.Set("X-Session-Token", c.token)
	req.Header[http.PHeaderOrderKey] = c.pho

	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("transport.Recv: round trip: %w", err)
	}
	return resp.Body, nil
}

// SendStream opens a long-lived POST with a streaming body.
// Data written to body is sent continuously as HTTP/2 DATA frames.
// The request completes when body returns io.EOF.
func (c *h2Conn) SendStream(ctx context.Context, path string, body io.Reader) (io.ReadCloser, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("transport.SendStream: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-Token", c.token)
	req.Header[http.PHeaderOrderKey] = c.pho

	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("transport.SendStream: round trip: %w", err)
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
	// Use the HTTP/2 ClientConn's own health state instead of probing the raw
	// connection.  A raw Read+SetReadDeadline races with the HTTP/2 framer's
	// concurrent reads on the same net.Conn, corrupting the framing layer and
	// killing the connection on every health-check cycle.
	if c.cc == nil {
		return false
	}
	return c.cc.CanTakeNewRequest()
}

// h2Dialer implements Dialer using uTLS + fhttp/http2.
type h2Dialer struct {
	cfg     H2Config
	helloID utls.ClientHelloID
	auth    auth.ClientAuth
}

// NewDialer returns a Dialer configured with the given H2Config and ClientAuth.
func NewDialer(cfg H2Config, a auth.ClientAuth) Dialer {
	return &h2Dialer{
		cfg:     cfg,
		helloID: utls.HelloChrome_Auto,
		auth:    a,
	}
}

func (d *h2Dialer) Dial(ctx context.Context, addr, sni string) (Conn, error) {
	// 1. Dial TCP with context support.
	// Use the caller-supplied NetDialer (e.g. Android socket protector) when
	// provided; fall back to a zero-value net.Dialer otherwise.
	netDialer := d.cfg.NetDialer
	if netDialer == nil {
		netDialer = &net.Dialer{}
	}
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport.Dial: TCP %s: %w", addr, err)
	}

	// 2. Create uTLS client and build handshake state for SessionID injection.
	uconn := utls.UClient(rawConn, &utls.Config{ServerName: sni}, d.helloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: build handshake: %w", err)
	}

	// 3. Inject authentication SessionID into the ClientHello.
	random := uconn.HandshakeState.Hello.Random
	sid, err := d.auth.InjectSessionID(random)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: inject session ID: %w", err)
	}
	uconn.HandshakeState.Hello.SessionId = sid
	// Patch raw ClientHello: offset 39 = type(1) + length(3) + version(2) + random(32) + sid_len(1)
	if len(uconn.HandshakeState.Hello.Raw) < 39+len(sid) {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: ClientHello Raw too short for SessionID patch")
	}
	copy(uconn.HandshakeState.Hello.Raw[39:39+len(sid)], sid)

	// 3b. Disable renegotiation in the uTLS config so ExportKeyingMaterial works.
	// uTLS Chrome presets include RenegotiationInfoExtension with
	// Renegotiation: RenegotiateOnceAsClient (matching real Chrome behavior).
	// Go's crypto/tls blocks ExportKeyingMaterial when renegotiation is enabled,
	// returning "ExportKeyingMaterial is unavailable when renegotiation is enabled".
	// Resetting the extension's Renegotiation field to RenegotiateNever and calling
	// ApplyConfig() updates the internal config without modifying Hello.Raw, so the
	// renegotiation_info extension bytes remain in the serialized ClientHello and
	// the TLS fingerprint is preserved.
	for _, ext := range uconn.Extensions {
		if ri, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			ri.Renegotiation = utls.RenegotiateNever
			break
		}
	}
	if err := uconn.ApplyConfig(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: apply config: %w", err)
	}

	// 4. Perform TLS handshake with injected SessionID.
	if deadline, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(deadline)
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport.Dial: TLS handshake: %w", err)
	}
	rawConn.SetDeadline(time.Time{})

	state := uconn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("transport.Dial: expected ALPN h2, got %q", state.NegotiatedProtocol)
	}
	slog.Debug("transport.Dial: TLS handshake complete",
		"addr", addr, "sni", sni, "alpn", state.NegotiatedProtocol,
		"tls_version", fmt.Sprintf("0x%04x", state.Version))

	// 5. Derive session token from TLS channel binding.
	cs := uconn.ConnectionState()
	binding, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("transport.Dial: export keying material: %w", err)
	}
	token, err := d.auth.DeriveSessionToken(binding)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("transport.Dial: derive session token: %w", err)
	}

	// 6. Create http2.Transport with Chrome SETTINGS from H2Config.
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

	// 7. Create HTTP/2 ClientConn on top of the uTLS connection.
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
		token:   token,
	}, nil
}
