package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ClientCheckConfig holds configuration for client-mode fingerprint checking.
type ClientCheckConfig struct {
	// EchoServiceURL is the fingerprint echo service URL.
	// Default: "https://tls.peet.ws/api/all"
	EchoServiceURL string

	// UTLSPreset is the uTLS ClientHello preset name.
	// Default: "HelloChrome_Auto"
	UTLSPreset string

	// ReferenceFile is the optional path to a reference JSON file.
	// If empty, DefaultChrome146Reference() is used.
	ReferenceFile string
}

// RunClientCheck connects to the echo service using uTLS, captures the
// fingerprint echo, and compares against the reference. Returns the comparison
// results, the actual fingerprint captured from the echo service, and any error.
func RunClientCheck(cfg ClientCheckConfig) ([]CheckResult, *Reference, error) {
	if cfg.EchoServiceURL == "" {
		cfg.EchoServiceURL = "https://tls.peet.ws/api/all"
	}
	if cfg.UTLSPreset == "" {
		cfg.UTLSPreset = "HelloChrome_Auto"
	}

	// Load or create reference.
	var expected *Reference
	if cfg.ReferenceFile != "" {
		var err error
		expected, err = LoadReference(cfg.ReferenceFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load reference: %w", err)
		}
	} else {
		expected = DefaultChrome146Reference()
	}

	// Connect and fetch.
	body, err := fetchEchoService(cfg.EchoServiceURL, cfg.UTLSPreset)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch echo service: %w", err)
	}

	// Parse response into Reference.
	actual, err := parseEchoResponse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("parse echo response: %w", err)
	}

	// Compare.
	results := Compare(actual, expected)
	return results, actual, nil
}

// ---------------------------------------------------------------------------
// Echo service response types (models tls.peet.ws/api/all JSON).
// ---------------------------------------------------------------------------

type echoResponse struct {
	IP          string    `json:"ip"`
	HTTPVersion string    `json:"http_version"`
	TLS         echoTLS   `json:"tls"`
	HTTP2       echoHTTP2 `json:"http2"`
}

type echoTLS struct {
	Ciphers              []string        `json:"ciphers"`
	Extensions           []echoExtension `json:"extensions"`
	JA3                  string          `json:"ja3"`
	JA3Hash              string          `json:"ja3_hash"`
	JA4                  string          `json:"ja4"`
	JA4R                 string          `json:"ja4_r"`
	TLSVersionRecord     string          `json:"tls_version_record"`
	TLSVersionNegotiated string          `json:"tls_version_negotiated"`
}

type echoExtension struct {
	Name string `json:"name"`
}

type echoHTTP2 struct {
	AkamaiFingerprint     string          `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string          `json:"akamai_fingerprint_hash"`
	SentFrames            []echoSentFrame `json:"sent_frames"`
}

type echoSentFrame struct {
	FrameType string   `json:"frame_type"`
	Length    int      `json:"length"`
	StreamID  int      `json:"stream_id"`
	Settings  []string `json:"settings,omitempty"`
	Increment int      `json:"increment,omitempty"`
	Headers   []string `json:"headers,omitempty"`
	Flags     []string `json:"flags,omitempty"`
}

// ---------------------------------------------------------------------------
// uTLS + HTTP/2 connection.
// ---------------------------------------------------------------------------

func fetchEchoService(rawURL, presetName string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL %q: %w", rawURL, err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	// TCP dial.
	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP dial %s: %w", net.JoinHostPort(host, port), err)
	}

	// uTLS handshake.
	preset := resolveUTLSPreset(presetName)
	tlsConn := tls.UClient(tcpConn, &tls.Config{ServerName: host}, *preset)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("uTLS handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("expected ALPN h2, got %q", state.NegotiatedProtocol)
	}

	// Create HTTP/2 client connection on top of the TLS connection.
	t2 := &http2.Transport{}
	cc, err := t2.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("http2 client conn: %w", err)
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("roundtrip: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read body: %w", err)
	}

	tlsConn.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func resolveUTLSPreset(name string) *tls.ClientHelloID {
	switch name {
	case "HelloChrome_Auto":
		return &tls.HelloChrome_Auto
	case "HelloChrome_120":
		return &tls.HelloChrome_120
	case "HelloFirefox_Auto":
		return &tls.HelloFirefox_Auto
	case "HelloFirefox_120":
		return &tls.HelloFirefox_120
	case "HelloSafari_Auto":
		return &tls.HelloSafari_Auto
	case "HelloEdge_Auto":
		return &tls.HelloEdge_Auto
	case "HelloIOS_Auto":
		return &tls.HelloIOS_Auto
	default:
		log.Printf("[fpcheck] Unknown uTLS preset %q, using HelloChrome_Auto", name)
		return &tls.HelloChrome_Auto
	}
}

// ---------------------------------------------------------------------------
// Response parsing — JSON → Reference.
// ---------------------------------------------------------------------------

// parseEchoResponse parses the JSON response from tls.peet.ws/api/all into
// a Reference struct suitable for comparison.
func parseEchoResponse(data []byte) (*Reference, error) {
	var resp echoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal echo response: %w", err)
	}

	now := time.Now().UTC()

	// Parse TLS fields.
	ja4 := resp.TLS.JA4
	extensions := parseExtensionIDs(resp.TLS.Extensions)
	alps := detectALPSCodepoint(extensions)
	cipherSuites := parseCipherSuites(resp.TLS.Ciphers)
	// ALPN: uTLS Chrome presets always offer ["h2", "http/1.1"].
	// The echo service confirms via http_version but doesn't return the
	// full ALPN list in a readily parseable form. Use the standard list.
	alpn := []string{"h2", "http/1.1"}

	// Parse H2 fields from Akamai fingerprint string.
	h2 := parseAkamaiFingerprint(resp.HTTP2.AkamaiFingerprint)

	return &Reference{
		Source:   fmt.Sprintf("Echo service capture at %s", now.Format(time.RFC3339)),
		Captured: now,
		TLS: TLSReference{
			JA4:           ja4,
			Extensions:    extensions,
			ALPSCodepoint: alps,
			CipherSuites:  cipherSuites,
			ALPN:          alpn,
		},
		H2:  h2,
		TCP: TCPReference{JA4T: nil},
	}, nil
}

// extIDRegexp matches a numeric ID in parentheses at the end of an extension
// name, e.g. "server_name (0)" → "0", "application_settings (17613)" → "17613".
var extIDRegexp = regexp.MustCompile(`\((\d+)\)\s*$`)

// parseExtensionIDs extracts numeric extension IDs from echo service extension names.
func parseExtensionIDs(exts []echoExtension) []uint16 {
	var ids []uint16
	for _, ext := range exts {
		m := extIDRegexp.FindStringSubmatch(ext.Name)
		if m == nil {
			continue
		}
		v, err := strconv.ParseUint(m[1], 10, 16)
		if err != nil {
			continue
		}
		ids = append(ids, uint16(v))
	}
	return ids
}

// detectALPSCodepoint looks for the ALPS extension ID (17513 old, 17613 new) in
// the extension list and returns whichever is found, or 0 if neither.
func detectALPSCodepoint(extIDs []uint16) uint16 {
	for _, id := range extIDs {
		if id == 17613 || id == 17513 {
			return id
		}
	}
	return 0
}

// cipherSuiteLookup maps well-known TLS cipher suite names to their numeric IDs.
var cipherSuiteLookup = map[string]uint16{
	"TLS_AES_128_GCM_SHA256":                        0x1301,
	"TLS_AES_256_GCM_SHA384":                        0x1302,
	"TLS_CHACHA20_POLY1305_SHA256":                  0x1303,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       0xc02b,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         0xc02f,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       0xc02c,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         0xc030,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   0xcca8,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            0xc013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            0xc014,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               0x009c,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               0x009d,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  0x002f,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  0x0035,
	// GREASE values reported by some echo services.
	"GREASE": 0,
}

// parseCipherSuites converts cipher suite names from the echo service to numeric IDs.
// Unknown names are logged and skipped.
func parseCipherSuites(names []string) []uint16 {
	var ids []uint16
	for _, name := range names {
		// Some services prefix with "TLS_GREASE_*" or just "GREASE".
		if strings.Contains(strings.ToUpper(name), "GREASE") {
			continue
		}
		id, ok := cipherSuiteLookup[name]
		if !ok {
			log.Printf("[fpcheck] Unknown cipher suite name %q, skipping", name)
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// parseAkamaiFingerprint parses the Akamai h2 fingerprint string into an H2Reference.
// Format: "SETTINGS|WINDOW_UPDATE|PRIORITY|PSH_ORDER"
func parseAkamaiFingerprint(fp string) H2Reference {
	ref := H2Reference{AkamaiString: fp}
	if fp == "" {
		return ref
	}

	parts := strings.SplitN(fp, "|", 4)

	if len(parts) >= 1 {
		ref.Settings = parts[0]
	}
	if len(parts) >= 2 {
		if v, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
			ref.WindowUpdate = uint32(v)
		}
	}
	if len(parts) >= 3 {
		if v, err := strconv.Atoi(parts[2]); err == nil {
			ref.Priority = v
		}
	}
	if len(parts) >= 4 {
		ref.PseudoHeaderOrder = parts[3]
	}

	return ref
}
