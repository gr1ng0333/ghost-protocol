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
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/framing"
	"ghost/internal/mux"
	"ghost/internal/shaping"

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
	Raw        []byte   // The complete ClientHello bytes that were peeked
	Random     []byte   // 32-byte ClientHello.Random
	SessionID  []byte   // Variable-length SessionID (typically 32 bytes for Ghost clients)
	ALPNProtos []string // ALPN protocol names from the ClientHello
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

	alpnProtos := parseALPN(raw, 44+sessionIDLen)

	return &clientHelloInfo{
		Raw:        raw,
		Random:     random,
		SessionID:  sessionID,
		ALPNProtos: alpnProtos,
	}, nil
}

// parseALPN extracts ALPN protocol names from raw ClientHello bytes.
// offset is where parsing continues after the SessionID field.
// Returns nil if ALPN is not present or cannot be parsed.
func parseALPN(raw []byte, offset int) []string {
	// Skip cipher suites
	if offset+2 > len(raw) {
		return nil
	}
	cipherLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2 + cipherLen

	// Skip compression methods
	if offset+1 > len(raw) {
		return nil
	}
	compLen := int(raw[offset])
	offset += 1 + compLen

	// Extensions length
	if offset+2 > len(raw) {
		return nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2

	end := offset + extensionsLen
	if end > len(raw) {
		end = len(raw)
	}

	// Walk extensions looking for ALPN (type 0x0010)
	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(raw[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > end {
			break
		}
		if extType == 0x0010 { // ALPN
			return decodeALPNList(raw[offset : offset+extLen])
		}
		offset += extLen
	}
	return nil
}

// decodeALPNList decodes the ALPN extension payload into protocol strings.
func decodeALPNList(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	data = data[:listLen]

	var protos []string
	for len(data) > 0 {
		pLen := int(data[0])
		data = data[1:]
		if pLen > len(data) {
			break
		}
		protos = append(protos, string(data[:pLen]))
		data = data[pLen:]
	}
	return protos
}

// ghostServer implements the Server interface.
type ghostServer struct {
	cfg         *config.ServerConfig
	tlsConfig   *tls.Config
	certMgr     *CertManager // certificate lifecycle manager (nil = use tlsConfig directly)
	serverAuth  auth.ServerAuth
	wrap        *mux.PipelineWrap // shared wrap (legacy); nil when per-session shaping
	sessionMgr  *SessionManager   // optional session lifecycle management
	profile     *shaping.Profile  // optional per-session shaping profile
	shapingMode shaping.Mode      // default shaping mode
	autoMode    bool              // auto mode switching
	listener    net.Listener
	sessions    chan Session
	mu          sync.Mutex
	closed      bool
	wg          sync.WaitGroup
}

// NewServer creates a new Ghost server.
// cfg is the server configuration.
// tlsCert is the TLS certificate for authenticated Ghost connections.
// sa is the ServerAuth for SessionID verification and token validation.
// wrap provides optional frame middleware (padding/shaping). Pass nil for no wrapping.
func NewServer(cfg *config.ServerConfig, tlsCert tls.Certificate, sa auth.ServerAuth, wrap *mux.PipelineWrap) Server {
	return &ghostServer{
		cfg: cfg,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
		serverAuth: sa,
		wrap:       wrap,
		sessions:   make(chan Session, 64),
	}
}

// NewServerWithSessions creates a Ghost server with session management
// and per-session traffic shaping. tlsConfig is the shared TLS configuration
// used for both authenticated and fallback connections. sm manages session
// lifecycle. profile, shapingMode, and autoMode control per-session shaping.
func NewServerWithSessions(cfg *config.ServerConfig, tlsConfig *tls.Config, sa auth.ServerAuth, sm *SessionManager, profile *shaping.Profile, shapingMode shaping.Mode, autoMode bool) Server {
	return &ghostServer{
		cfg:         cfg,
		tlsConfig:   tlsConfig,
		serverAuth:  sa,
		sessionMgr:  sm,
		profile:     profile,
		shapingMode: shapingMode,
		autoMode:    autoMode,
		sessions:    make(chan Session, 64),
	}
}

// SetCertManager configures the server to use a CertManager for TLS certificates.
// When set, tlsConfig is replaced by certMgr.TLSConfig().
func (s *ghostServer) SetCertManager(cm *CertManager) {
	s.certMgr = cm
	s.tlsConfig = cm.TLSConfig()
}

// serverStatsProvider tracks per-session mux statistics for the shaping
// subsystem. It satisfies shaping.MuxStatsProvider.
type serverStatsProvider struct {
	activeStreams atomic.Int64
	bytesSent     atomic.Uint64
	bytesRecv     atomic.Uint64
}

// ActiveStreamCount returns the number of active streams.
func (p *serverStatsProvider) ActiveStreamCount() int { return int(p.activeStreams.Load()) }

// TotalBytesSent returns the total bytes sent to clients.
func (p *serverStatsProvider) TotalBytesSent() uint64 { return p.bytesSent.Load() }

// TotalBytesRecv returns the total bytes received from clients.
func (p *serverStatsProvider) TotalBytesRecv() uint64 { return p.bytesRecv.Load() }

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
// Checks for ACME TLS-ALPN-01 challenges first, then Ghost auth, then fallback.
func (s *ghostServer) handleConn(ctx context.Context, conn *peekConn, chi *clientHelloInfo, fallback string) {
	// ACME TLS-ALPN-01 challenge: route to TLS termination with autocert.
	if containsALPN(chi.ALPNProtos, "acme-tls/1") {
		slog.Debug("server: ACME TLS-ALPN-01 challenge detected", "remote", conn.RemoteAddr())
		s.handleFallback(ctx, conn, fallback)
		return
	}

	router := newConnRouter(s.serverAuth)
	mode, sharedSecret := router.route(chi)

	switch mode {
	case routeGhost:
		s.handleGhost(ctx, conn, chi, sharedSecret)
	case routeFallback:
		s.handleFallback(ctx, conn, fallback)
	}
}

// containsALPN checks if the protocol list contains the given protocol.
func containsALPN(protos []string, target string) bool {
	for _, p := range protos {
		if p == target {
			return true
		}
	}
	return false
}

// handleGhost performs the TLS handshake and serves HTTP/2 for authenticated Ghost clients.
// It wires a ServerMux to the handler via io.Pipe pairs, starts per-session shaping
// (cover traffic + stats updater), and registers the session with SessionManager.
func (s *ghostServer) handleGhost(ctx context.Context, conn *peekConn, chi *clientHelloInfo, sharedSecret [32]byte) {
	tlsConn := tls.Server(conn, s.tlsConfig)
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

	// Build FrameWriter/FrameReader chain.
	var writer framing.FrameWriter = &framing.EncoderWriter{Enc: framing.NewEncoder(downW)}
	var reader framing.FrameReader = &framing.DecoderReader{Dec: framing.NewDecoder(upR)}

	var timerWriter *shaping.TimerFrameWriter
	var selector *shaping.AdaptiveSelector

	if s.profile != nil {
		// Per-session shaping: fresh padder/timer/selector per connection.
		seed := time.Now().UnixNano()
		padder := shaping.NewProfilePadder(s.profile, seed)
		timer := shaping.NewProfileTimer(s.profile, seed+1)
		selector = shaping.NewAdaptiveSelector(s.shapingMode, s.autoMode)

		padWriter := &shaping.PadderFrameWriter{Padder: padder, Next: writer}
		timerWriter = &shaping.TimerFrameWriter{
			Timer: timer, Selector: selector, Next: padWriter,
		}
		writer = timerWriter

		reader = &shaping.UnpadderFrameReader{Padder: padder, Src: reader}
	} else if s.wrap != nil {
		// Legacy shared wrap (no per-session shaping).
		if s.wrap.WrapWriter != nil {
			writer = s.wrap.WrapWriter(writer)
		}
		if s.wrap.WrapReader != nil {
			reader = s.wrap.WrapReader(reader)
		}
	}

	serverMux := mux.NewServerMux(writer, reader)
	stats := &serverStatsProvider{}

	// Start per-session cover traffic and stats updater.
	var cleanupShaping func()
	if s.profile != nil && timerWriter != nil && selector != nil {
		shapingCtx, shapingCancel := context.WithCancel(ctx)
		seed := time.Now().UnixNano()
		cover := shaping.NewCoverGenerator(timerWriter, selector, s.profile, seed)
		cover.Start(shapingCtx)

		updater := shaping.NewStatsUpdater(stats, timerWriter, cover, 1*time.Second)
		go updater.Run(shapingCtx)

		cleanupShaping = func() {
			cover.Stop()
			shapingCancel()
		}
	} else {
		cleanupShaping = func() {}
	}

	sessionID := generateSessionID()

	// Register with session manager if available.
	if s.sessionMgr != nil {
		if err := s.sessionMgr.Register(sessionID, tlsConn.RemoteAddr(), serverMux, cleanupShaping); err != nil {
			cleanupShaping()
			serverMux.Close()
			upW.Close()
			upR.Close()
			downW.Close()
			downR.Close()
			slog.Warn("ghost: session rejected", "reason", err, "remote", tlsConn.RemoteAddr())
			return
		}
	}

	// Derive per-session paths.
	uploadPath, downloadPath := mux.DerivePaths(sharedSecret)

	// Create handler wired to pipes.
	handler := newGhostHandler(s.serverAuth, sharedSecret, binding, upW, downR, uploadPath, downloadPath)
	handler.sessionMgr = s.sessionMgr
	handler.sessionID = sessionID

	// Start stream dispatch loop.
	go s.dispatchStreams(ctx, serverMux, stats)

	sess := &ghostSession{
		id:         sessionID,
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
		if s.sessionMgr != nil {
			s.sessionMgr.Remove(sessionID)
		} else {
			cleanupShaping()
			serverMux.Close()
		}
		upW.Close()
		upR.Close()
		downW.Close()
		downR.Close()
		return
	}

	slog.Info("ghost: session established", "remote", conn.RemoteAddr(), "session", truncID(sessionID))

	defer func() {
		if s.sessionMgr != nil {
			s.sessionMgr.Remove(sessionID)
		} else {
			cleanupShaping()
			serverMux.Close()
		}
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
func (s *ghostServer) dispatchStreams(ctx context.Context, smux mux.ServerMux, stats *serverStatsProvider) {
	for {
		stream, dest, err := smux.Accept(ctx)
		if err != nil {
			return // mux closed
		}
		go s.handleStream(ctx, stream, dest, stats)
	}
}

// handleStream dials the real destination and copies data bidirectionally.
func (s *ghostServer) handleStream(ctx context.Context, stream mux.Stream, dest mux.Destination, stats *serverStatsProvider) {
	defer stream.Close()

	stats.activeStreams.Add(1)
	defer stats.activeStreams.Add(-1)

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
		n, _ := io.Copy(target, stream) // client → destination
		stats.bytesRecv.Add(uint64(n))
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()

	n, _ := io.Copy(stream, target) // destination → client
	stats.bytesSent.Add(uint64(n))
	<-done
}

// handleFallback terminates TLS and reverse-proxies the plaintext HTTP
// to the fallback backend (e.g. Caddy on :8080).
func (s *ghostServer) handleFallback(ctx context.Context, conn *peekConn, fallback string) {
	if fallback == "" {
		slog.Warn("ghost: no fallback configured, closing connection", "remote", conn.RemoteAddr())
		conn.Close()
		return
	}

	// Terminate TLS using the same cert as Ghost mode.
	tlsConn := tls.Server(conn, s.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("fallback: TLS handshake failed", "err", err, "remote", conn.RemoteAddr())
		tlsConn.Close()
		return
	}
	tlsConn.SetDeadline(time.Time{}) // clear deadline

	slog.Debug("ghost: reverse-proxying to fallback", "remote", conn.RemoteAddr(), "fallback", fallback)

	// Reverse proxy decrypted HTTP to fallback backend.
	target := &url.URL{Scheme: "http", Host: fallback}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)

	srv := &http.Server{
		Handler:     proxy,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	http2.ConfigureServer(srv, nil)

	ln := newSingleConnListener(tlsConn)

	// Shut down when parent context is done.
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	srv.Serve(ln)
}

// singleConnListener is a net.Listener that yields one connection then blocks.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	ch   chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, ch: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	// Block until Close is called.
	<-l.ch
	return nil, errors.New("listener closed")
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.ch:
	default:
		close(l.ch)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
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
