package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------------------
// Reference structs — duplicated from tools/fpcheck/reference.go.
// These must stay in sync (same JSON tags) so output is compatible.
// ---------------------------------------------------------------------------

// Reference holds all expected fingerprint values for a browser profile.
type Reference struct {
	Source   string       `json:"source"`
	Captured time.Time    `json:"captured"`
	TLS      TLSReference `json:"tls"`
	H2       H2Reference  `json:"h2"`
	TCP      TCPReference `json:"tcp"`
}

// TLSReference holds TLS ClientHello fingerprint fields.
type TLSReference struct {
	JA4           string   `json:"ja4"`
	Extensions    []uint16 `json:"extensions"`
	ALPSCodepoint uint16   `json:"alps_codepoint"`
	CipherSuites  []uint16 `json:"cipher_suites"`
	ALPN          []string `json:"alpn"`
}

// H2Reference holds HTTP/2 connection-level fingerprint fields.
type H2Reference struct {
	Settings          string `json:"settings"`
	WindowUpdate      uint32 `json:"window_update"`
	Priority          int    `json:"priority"`
	PseudoHeaderOrder string `json:"pseudo_header_order"`
	AkamaiString      string `json:"akamai_string"`
}

// TCPReference holds TCP-level fingerprint fields.
type TCPReference struct {
	JA4T *string `json:"ja4t"`
}

// captureOutput is the full JSON printed to stdout (superset of Reference).
type captureOutput struct {
	Source     string       `json:"source"`
	Captured   time.Time    `json:"captured"`
	ClientAddr string       `json:"client_addr"`
	TLS        tlsOutput    `json:"tls"`
	H2         H2Reference  `json:"h2"`
	TCP        TCPReference `json:"tcp"`
}

type tlsOutput struct {
	JA4           string   `json:"ja4"`
	Extensions    []uint16 `json:"extensions"`
	ALPSCodepoint uint16   `json:"alps_codepoint"`
	CipherSuites  []uint16 `json:"cipher_suites"`
	ALPN          []string `json:"alpn"`
	Note          string   `json:"note"`
}

// ---------------------------------------------------------------------------
// teeConn — wraps net.Conn and copies read bytes into a buffer.
// ---------------------------------------------------------------------------

type teeConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		t.buf.Write(p[:n])
		t.mu.Unlock()
	}
	return n, err
}

func (t *teeConn) snapshot() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]byte, t.buf.Len())
	copy(out, t.buf.Bytes())
	return out
}

// ---------------------------------------------------------------------------
// connData — per-connection captured data.
// ---------------------------------------------------------------------------

type connData struct {
	mu           sync.Mutex
	clientAddr   string
	cipherSuites []uint16
	alpn         []string
	tee          *teeConn
}

// ---------------------------------------------------------------------------
// Self-signed certificate generation.
// ---------------------------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------------------------
// HTTP/2 frame parsing from raw bytes.
// ---------------------------------------------------------------------------

const (
	h2PrefaceLen   = 24 // len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	frameHeaderLen = 9
	frameSettings  = 0x04
	frameWindowUpd = 0x08
	frameHeaders   = 0x01
	framePriority  = 0x02
)

type h2Fingerprint struct {
	Settings          string
	WindowUpdate      uint32
	Priority          int
	PseudoHeaderOrder string
}

func (f *h2Fingerprint) AkamaiString() string {
	return fmt.Sprintf("%s|%d|%d|%s",
		f.Settings, f.WindowUpdate, f.Priority, f.PseudoHeaderOrder)
}

func parseH2Frames(raw []byte) (*h2Fingerprint, error) {
	// Skip the 24-byte HTTP/2 connection preface if present.
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if bytes.HasPrefix(raw, preface) {
		raw = raw[h2PrefaceLen:]
	}

	fp := &h2Fingerprint{}
	var settingsParts []string
	foundHeaders := false

	for len(raw) >= frameHeaderLen {
		length := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
		ftype := raw[3]
		// flags := raw[4]
		streamID := binary.BigEndian.Uint32(raw[5:9]) & 0x7FFFFFFF

		raw = raw[frameHeaderLen:]
		if len(raw) < length {
			break // incomplete frame
		}
		payload := raw[:length]
		raw = raw[length:]

		switch ftype {
		case frameSettings:
			if streamID == 0 && length%6 == 0 {
				for i := 0; i+6 <= length; i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", id, val))
				}
			}
		case frameWindowUpd:
			if streamID == 0 && length == 4 {
				fp.WindowUpdate = binary.BigEndian.Uint32(payload[:4]) & 0x7FFFFFFF
			}
		case framePriority:
			fp.Priority++
		case frameHeaders:
			if !foundHeaders {
				foundHeaders = true
				fp.PseudoHeaderOrder = extractPseudoHeaderOrder(payload, streamID)
			}
		}
	}

	fp.Settings = strings.Join(settingsParts, ";")
	return fp, nil
}

func extractPseudoHeaderOrder(payload []byte, streamID uint32) string {
	// HEADERS frame may include padding and priority data.
	// We need to check the flags from the frame header, but we've already
	// consumed it. For simplicity, try HPACK decode directly; if it fails
	// with padding/priority bytes, try skipping 5 bytes (priority size).
	order := tryHPACKDecode(payload)
	if len(order) == 0 && len(payload) > 5 {
		// Possibly has priority fields (5 bytes: stream dep 4 + weight 1).
		order = tryHPACKDecode(payload[5:])
	}
	return strings.Join(order, ",")
}

var pseudoMap = map[string]string{
	":method":    "m",
	":authority": "a",
	":scheme":    "s",
	":path":      "p",
}

func tryHPACKDecode(data []byte) []string {
	var order []string
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if short, ok := pseudoMap[f.Name]; ok {
			order = append(order, short)
		}
	})
	// Write may fail if the data has padding or extra bytes — that's okay.
	_, _ = dec.Write(data)
	return order
}

// ---------------------------------------------------------------------------
// Server core.
// ---------------------------------------------------------------------------

type server struct {
	addr    string
	outPath string
	once    bool
	doneCh  chan struct{} // closed after first capture when -once is set
}

func (s *server) run() error {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}
	log.Println("[profcap] Generated self-signed certificate for localhost")

	// Per-connection data, keyed by remote address.
	connMap := &sync.Map{}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			cd := &connData{
				clientAddr:   hello.Conn.RemoteAddr().String(),
				cipherSuites: hello.CipherSuites,
				alpn:         hello.SupportedProtos,
			}
			connMap.Store(hello.Conn.RemoteAddr().String(), cd)
			return nil, nil
		},
	}

	ln, err := tls.Listen("tcp", s.addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	defer ln.Close()

	log.Printf("[profcap] Listening on https://localhost%s\n", s.addr)
	log.Println("[profcap] Open in Chrome and accept the certificate warning")

	// Wrap listener to inject teeConn.
	wrappedLn := &teeListener{
		Listener: ln,
		connMap:  connMap,
	}

	h2srv := &http2.Server{}
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handleRequest(w, r, connMap)
		}),
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	s.doneCh = make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			log.Println("[profcap] Shutting down...")
			ln.Close()
		case <-s.doneCh:
			ln.Close()
		}
	}()

	for {
		conn, err := wrappedLn.Accept()
		if err != nil {
			select {
			case <-s.doneCh:
				return nil
			default:
			}
			// If listener is closed, exit cleanly.
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil
			}
			log.Printf("[profcap] Accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			h2srv.ServeConn(c, &http2.ServeConnOpts{
				Handler: httpSrv.Handler,
			})
		}(conn)
	}
}

func (s *server) handleRequest(w http.ResponseWriter, r *http.Request, connMap *sync.Map) {
	// Ignore favicon and other noise.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	remoteAddr := r.RemoteAddr
	now := time.Now().UTC()

	// Retrieve TLS capture data.
	var cipherSuites []uint16
	var alpn []string
	if val, ok := connMap.Load(remoteAddr); ok {
		cd := val.(*connData)
		cd.mu.Lock()
		cipherSuites = cd.cipherSuites
		alpn = cd.alpn
		cd.mu.Unlock()
	}

	// Retrieve teeConn for HTTP/2 frame parsing.
	var fp *h2Fingerprint
	if val, ok := connMap.Load("tee:" + remoteAddr); ok {
		tee := val.(*teeConn)
		raw := tee.snapshot()
		var err error
		fp, err = parseH2Frames(raw)
		if err != nil {
			log.Printf("[profcap] Frame parse error for %s: %v", remoteAddr, err)
		}
	}
	if fp == nil {
		fp = &h2Fingerprint{}
	}

	// Build output.
	h2Ref := H2Reference{
		Settings:          fp.Settings,
		WindowUpdate:      fp.WindowUpdate,
		Priority:          fp.Priority,
		PseudoHeaderOrder: fp.PseudoHeaderOrder,
		AkamaiString:      fp.AkamaiString(),
	}

	output := captureOutput{
		Source:     fmt.Sprintf("Captured from client connection at %s", now.Format(time.RFC3339)),
		Captured:   now,
		ClientAddr: remoteAddr,
		TLS: tlsOutput{
			JA4:           "",
			Extensions:    []uint16{},
			ALPSCodepoint: 0,
			CipherSuites:  cipherSuites,
			ALPN:          alpn,
			Note:          "Extension list incomplete — ClientHelloInfo does not expose all extensions. Use pcap capture for full extension list and JA4 computation.",
		},
		H2:  h2Ref,
		TCP: TCPReference{JA4T: nil},
	}

	// Print JSON to stdout.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		log.Printf("[profcap] JSON encode error: %v", err)
	}

	// Save Reference JSON if -out specified.
	if s.outPath != "" {
		ref := &Reference{
			Source:   output.Source,
			Captured: output.Captured,
			TLS: TLSReference{
				JA4:           "",
				Extensions:    output.TLS.Extensions,
				ALPSCodepoint: output.TLS.ALPSCodepoint,
				CipherSuites:  output.TLS.CipherSuites,
				ALPN:          output.TLS.ALPN,
			},
			H2:  h2Ref,
			TCP: TCPReference{JA4T: nil},
		}
		if err := saveReference(ref, s.outPath); err != nil {
			log.Printf("[profcap] Save error: %v", err)
		} else {
			log.Printf("[profcap] Saved reference to %s", s.outPath)
		}
	}

	// Respond with HTML.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	cipherStr := formatUint16Slice(cipherSuites)
	alpnStr := strings.Join(alpn, ", ")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Ghost profcap</title></head><body>
<h1>Ghost profcap &mdash; Fingerprint Captured</h1>
<h2>HTTP/2 Fingerprint</h2>
<pre>Settings:       %s</pre>
<pre>Window Update:  %d</pre>
<pre>Priority:       %d</pre>
<pre>PSH Order:      %s</pre>
<pre>Akamai:         %s</pre>
<h2>TLS</h2>
<pre>Cipher suites:  %s</pre>
<pre>ALPN:           [%s]</pre>
<p><em>Note: Extension list incomplete &mdash; use pcap capture for full extension list and JA4.</em></p>
</body></html>`,
		html.EscapeString(fp.Settings),
		fp.WindowUpdate,
		fp.Priority,
		html.EscapeString(fp.PseudoHeaderOrder),
		html.EscapeString(fp.AkamaiString()),
		html.EscapeString(cipherStr),
		html.EscapeString(alpnStr),
	)

	// If -once, signal shutdown.
	if s.once {
		select {
		case <-s.doneCh:
		default:
			close(s.doneCh)
		}
	}
}

// ---------------------------------------------------------------------------
// teeListener — wraps accepted connections in teeConn.
// ---------------------------------------------------------------------------

type teeListener struct {
	net.Listener
	connMap *sync.Map
}

func (tl *teeListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tc := &teeConn{Conn: conn}
	// Store the teeConn keyed by remote address so the handler can retrieve it.
	tl.connMap.Store("tee:"+conn.RemoteAddr().String(), tc)
	return tc, nil
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func formatUint16Slice(s []uint16) string {
	if len(s) == 0 {
		return "[]"
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func saveReference(ref *Reference, path string) error {
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal reference: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write reference %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

func main() {
	addr := flag.String("addr", ":8443", "Listen address")
	outPath := flag.String("out", "", "Output file path for Reference JSON")
	once := flag.Bool("once", false, "Exit after capturing one connection")
	flag.Parse()

	s := &server{
		addr:    *addr,
		outPath: *outPath,
		once:    *once,
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("")

	if err := s.run(); err != nil {
		log.Fatalf("[profcap] Fatal: %v", err)
	}
}
