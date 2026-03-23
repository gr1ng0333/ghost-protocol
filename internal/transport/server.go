package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/framing"
	"ghost/internal/mux"

	"golang.org/x/net/http2"
)

// ErrNotImplemented is returned by Session methods not yet available in Stage 2.2.
var ErrNotImplemented = errors.New("not implemented in Stage 2.2")

// Session represents a single authenticated client session.
type Session interface {
	// ID returns the unique session identifier.
	ID() string
	// RemoteAddr returns the remote address of the client.
	RemoteAddr() net.Addr
	// Receive blocks until a payload is available or ctx is cancelled.
	Receive(ctx context.Context) ([]byte, error)
	// Send transmits a payload to the client.
	Send(ctx context.Context, payload []byte) error
	// Close terminates the session.
	Close() error
}

// Listener accepts authenticated Ghost sessions.
type Listener interface {
	// Accept blocks until an authenticated session is available or ctx is cancelled.
	Accept(ctx context.Context) (Session, error)

	// Close stops accepting new sessions.
	Close() error
}

// Server is the Ghost server interface.
type Server interface {
	// ListenAndServe starts the server on the given address.
	// fallback is the address of the fallback web server for unauthenticated connections.
	ListenAndServe(ctx context.Context, addr, fallback string) error

	// Close stops the server gracefully.
	Close() error
}

// peekConn wraps a net.Conn, allowing the first bytes to be read (peeked)
// and then replayed to subsequent readers. This is essential for reading
// the TLS ClientHello before deciding how to handle the connection.
type peekConn struct {
	net.Conn
	reader io.Reader
}

// newPeekConn reads up to n bytes from conn without consuming them
// from the perspective of future readers. Returns the peeked bytes
// and a peekConn whose Read() replays those bytes first.
func newPeekConn(conn net.Conn, n int) (*peekConn, []byte, error) {
	buf := make([]byte, n)
	nr, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("peekConn: read: %w", err)
	}
	buf = buf[:nr]

	pc := &peekConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(buf), conn),
	}
	return pc, buf, nil
}

// Read delegates to the MultiReader, replaying peeked bytes first.
func (pc *peekConn) Read(p []byte) (int, error) {
	return pc.reader.Read(p)
}

// clientHelloInfo holds the extracted fields from a TLS ClientHello
// that Ghost needs for authentication routing.
type clientHelloInfo struct {
	Raw       []byte // The complete ClientHello bytes that were peeked
	Random    []byte // 32-byte ClientHello.Random
	SessionID []byte // Variable-length SessionID (typically 32 bytes for Ghost clients)
}

// parseClientHello extracts Random and SessionID from raw bytes
// that start with a TLS record. Returns error if the bytes don't
// contain a valid ClientHello.
func parseClientHello(raw []byte) (*clientHelloInfo, error) {
	// Minimum: 5 (record header) + 4 (handshake header) + 2 (client version) + 32 (random) + 1 (session ID len) = 44
	if len(raw) < 44 {
		return nil, fmt.Errorf("parseClientHello: data too short (%d bytes, need at least 44)", len(raw))
	}

	// Byte 0: ContentType = 0x16 (Handshake)
	if raw[0] != 0x16 {
		return nil, fmt.Errorf("parseClientHello: wrong content type 0x%02x, want 0x16", raw[0])
	}

	// Bytes 1-2: ProtocolVersion (skip validation, accept any)
	// Bytes 3-4: Record length
	recordLen := binary.BigEndian.Uint16(raw[3:5])
	if int(recordLen)+5 > len(raw) {
		return nil, fmt.Errorf("parseClientHello: record length %d exceeds data (%d bytes available)", recordLen, len(raw)-5)
	}

	// Byte 5: HandshakeType = 0x01 (ClientHello)
	if raw[5] != 0x01 {
		return nil, fmt.Errorf("parseClientHello: wrong handshake type 0x%02x, want 0x01", raw[5])
	}

	// Bytes 6-8: Handshake length (uint24) — skip validation, we use field offsets
	// Bytes 9-10: ClientVersion
	// Bytes 11-42: Random (32 bytes)
	random := make([]byte, 32)
	copy(random, raw[11:43])

	// Byte 43: SessionID length
	sessionIDLen := int(raw[43])
	if 44+sessionIDLen > len(raw) {
		return nil, fmt.Errorf("parseClientHello: session ID length %d exceeds data", sessionIDLen)
	}

	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, raw[44:44+sessionIDLen])

	return &clientHelloInfo{
		Raw:       raw,
		Random:    random,
		SessionID: sessionID,
	}, nil
}

// ghostServer implements the Server interface.
type ghostServer struct {
	cfg        *config.ServerConfig
	tlsCert    tls.Certificate
	serverAuth auth.ServerAuth
	wrap       *mux.PipelineWrap
	listener   net.Listener
	sessions   chan Session
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
}

// NewServer creates a new Ghost server.
// cfg is the server configuration.
// tlsCert is the TLS certificate for authenticated Ghost connections.
// sa is the ServerAuth for SessionID verification and token validation.
// wrap provides optional frame middleware (padding/shaping). Pass nil for no wrapping.
func NewServer(cfg *config.ServerConfig, tlsCert tls.Certificate, sa auth.ServerAuth, wrap *mux.PipelineWrap) Server {
	return &ghostServer{
		cfg:        cfg,
		tlsCert:    tlsCert,
		serverAuth: sa,
		wrap:       wrap,
		sessions:   make(chan Session, 64),
	}
}

// Addr returns the listener's address, or nil if not yet listening.
func (s *ghostServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// ListenAndServe implements Server. It opens a TCP listener on addr,
// peeks at each connection's TLS ClientHello, parses the Random and
// SessionID fields, and dispatches to handleConn in a goroutine.
func (s *ghostServer) ListenAndServe(ctx context.Context, addr, fallback string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server.ListenAndServe: listen %s: %w", addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	slog.Info("server.ListenAndServe: listening", "addr", ln.Addr().String())

	// Close listener when context is cancelled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			slog.Warn("server.ListenAndServe: accept error", "err", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleIncoming(ctx, conn, fallback)
		}()
	}
}

// Close implements Server. Closes listener, waits for active connections, sets closed.
func (s *ghostServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	s.mu.Unlock()

	var errs []error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("server.Close: listener: %w", err))
		}
	}

	s.wg.Wait()
	close(s.sessions)

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// handleIncoming peeks at a connection, parses the ClientHello, and dispatches.
func (s *ghostServer) handleIncoming(ctx context.Context, conn net.Conn, fallback string) {
	pc, raw, err := newPeekConn(conn, 4096)
	if err != nil {
		slog.Warn("server: peek failed", "remote", conn.RemoteAddr(), "err", err)
		conn.Close()
		return
	}

	chi, err := parseClientHello(raw)
	if err != nil {
		slog.Warn("server: ClientHello parse failed", "remote", conn.RemoteAddr(), "err", err)
		conn.Close()
		return
	}

	s.handleConn(ctx, pc, chi, fallback)
}

// handleConn routes the connection based on ClientHello authentication.
func (s *ghostServer) handleConn(ctx context.Context, conn *peekConn, chi *clientHelloInfo, fallback string) {
	router := newConnRouter(s.serverAuth)
	mode, sharedSecret := router.route(chi)

	switch mode {
	case routeGhost:
		s.handleGhost(ctx, conn, chi, sharedSecret)
	case routeFallback:
		s.handleFallback(ctx, conn, fallback)
	}
}

// handleGhost performs the TLS handshake and serves HTTP/2 for authenticated Ghost clients.
// It wires a ServerMux to the handler via io.Pipe pairs and starts a stream dispatch loop.
func (s *ghostServer) handleGhost(ctx context.Context, conn *peekConn, chi *clientHelloInfo, sharedSecret [32]byte) {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("ghost: TLS handshake failed", "err", err, "remote", conn.RemoteAddr())
		conn.Close()
		return
	}
	defer tlsConn.Close()

	// Close the TLS connection when the server context is cancelled.
	go func() {
		<-ctx.Done()
		tlsConn.Close()
	}()

	slog.Info("ghost: serving HTTP/2", "remote", conn.RemoteAddr())

	// Derive channel binding for token verification.
	cs := tlsConn.ConnectionState()
	binding, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		slog.Warn("ghost: export keying material failed", "err", err, "remote", conn.RemoteAddr())
		return
	}

	// Create pipes for mux ↔ handler communication.
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	// Build FrameWriter/FrameReader chain with optional middleware.
	var writer framing.FrameWriter = &framing.EncoderWriter{Enc: framing.NewEncoder(downW)}
	var reader framing.FrameReader = &framing.DecoderReader{Dec: framing.NewDecoder(upR)}
	if s.wrap != nil {
		if s.wrap.WrapWriter != nil {
			writer = s.wrap.WrapWriter(writer)
		}
		if s.wrap.WrapReader != nil {
			reader = s.wrap.WrapReader(reader)
		}
	}
	serverMux := mux.NewServerMux(writer, reader)

	// Derive per-session paths.
	uploadPath, downloadPath := mux.DerivePaths(sharedSecret)

	// Create handler wired to pipes.
	handler := newGhostHandler(s.serverAuth, sharedSecret, binding, upW, downR, uploadPath, downloadPath)

	// Start stream dispatch loop.
	go s.dispatchStreams(ctx, serverMux)

	sess := &ghostSession{
		id:         generateSessionID(),
		remoteAddr: conn.RemoteAddr(),
		serverMux:  serverMux,
		upW:        upW,
		downW:      downW,
		done:       make(chan struct{}),
	}

	select {
	case s.sessions <- sess:
	default:
		slog.Warn("ghost: sessions channel full, dropping connection", "remote", conn.RemoteAddr())
		return
	}

	slog.Info("ghost: session established", "remote", conn.RemoteAddr(), "session", sess.id)

	defer func() {
		serverMux.Close()
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
		sess.Close()
	}()

	// Serve HTTP/2 (blocks until connection closes).
	h2srv := &http2.Server{}
	h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

// dispatchStreams accepts streams from the ServerMux and dials destinations.
func (s *ghostServer) dispatchStreams(ctx context.Context, smux mux.ServerMux) {
	for {
		stream, dest, err := smux.Accept(ctx)
		if err != nil {
			return // mux closed
		}
		go s.handleStream(ctx, stream, dest)
	}
}

// handleStream dials the real destination and copies data bidirectionally.
func (s *ghostServer) handleStream(ctx context.Context, stream mux.Stream, dest mux.Destination) {
	defer stream.Close()

	addr := net.JoinHostPort(dest.Addr, strconv.Itoa(int(dest.Port)))
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		slog.Warn("ghost: dial destination", "addr", addr, "err", err)
		return
	}
	defer target.Close()

	// Bidirectional copy.
	done := make(chan struct{})
	go func() {
		io.Copy(target, stream) // client → destination
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()

	io.Copy(stream, target) // destination → client
	<-done
}

// handleFallback splices the connection to the fallback backend.
func (s *ghostServer) handleFallback(ctx context.Context, conn *peekConn, fallback string) {
	if fallback == "" {
		slog.Warn("ghost: no fallback configured, closing connection", "remote", conn.RemoteAddr())
		conn.Close()
		return
	}
	slog.Debug("ghost: splicing to fallback", "remote", conn.RemoteAddr(), "fallback", fallback)
	if err := splice(ctx, conn, nil, fallback); err != nil {
		slog.Debug("ghost: fallback splice ended", "err", err, "remote", conn.RemoteAddr())
	}
}

// ghostSession represents an authenticated client session backed by a ServerMux.
type ghostSession struct {
	id         string
	remoteAddr net.Addr
	serverMux  mux.ServerMux
	upW        *io.PipeWriter
	downW      *io.PipeWriter
	done       chan struct{}
	closeOnce  sync.Once
}

func (gs *ghostSession) ID() string           { return gs.id }
func (gs *ghostSession) RemoteAddr() net.Addr { return gs.remoteAddr }
func (gs *ghostSession) Close() error {
	gs.closeOnce.Do(func() { close(gs.done) })
	return nil
}
func (gs *ghostSession) Receive(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("ghostSession.Receive: use mux.Accept() instead: %w", ErrNotImplemented)
}
func (gs *ghostSession) Send(ctx context.Context, payload []byte) error {
	return fmt.Errorf("ghostSession.Send: use mux streams instead: %w", ErrNotImplemented)
}

// generateSessionID returns a random 32-character hex string.
func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ghostListener implements the Listener interface as a thin wrapper
// reading from the sessions channel.
type ghostListener struct {
	sessions <-chan Session
	done     chan struct{}
	once     sync.Once
}

// Accept blocks until an authenticated session is available or ctx is cancelled.
func (l *ghostListener) Accept(ctx context.Context) (Session, error) {
	select {
	case s, ok := <-l.sessions:
		if !ok {
			return nil, errors.New("listener: closed")
		}
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.done:
		return nil, errors.New("listener: closed")
	}
}

// Close stops accepting new sessions.
func (l *ghostListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// GenerateSelfSignedCert creates a self-signed TLS certificate for testing.
// domain is the CN/SAN (e.g., "example.com").
func GenerateSelfSignedCert(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generateSelfSignedCert: generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generateSelfSignedCert: serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generateSelfSignedCert: create cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        template,
	}, nil
}
