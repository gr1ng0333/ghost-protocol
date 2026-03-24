package transport

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertManager_SelfSigned_GetCertificate(t *testing.T) {
	cm, err := NewCertManager("example.com", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.Mode() != "selfsigned" {
		t.Fatalf("mode = %q, want selfsigned", cm.Mode())
	}

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil cert")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cert has no DER data")
	}

	// Parse to verify it's a valid cert for the domain.
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := x.VerifyHostname("example.com"); err != nil {
		t.Errorf("VerifyHostname: %v", err)
	}
}

func TestCertManager_Manual_LoadsCert(t *testing.T) {
	// Generate a self-signed cert and write to temp files.
	tlsCert, err := GenerateSelfSignedCert("manual.test")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	writeCertAndKey(t, certFile, keyFile, tlsCert)

	cm, err := NewCertManager("manual.test", false, "", "", certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.Mode() != "manual" {
		t.Fatalf("mode = %q, want manual", cm.Mode())
	}

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "manual.test"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}
}

func TestCertManager_Manual_ReloadCert(t *testing.T) {
	tlsCert, err := GenerateSelfSignedCert("reload.test")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	writeCertAndKey(t, certFile, keyFile, tlsCert)

	cm, err := NewCertManager("reload.test", false, "", "", certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// Get initial cert serial.
	cert1, _ := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "reload.test"})
	x1, _ := x509.ParseCertificate(cert1.Certificate[0])

	// Generate and write a new cert.
	tlsCert2, _ := GenerateSelfSignedCert("reload.test")
	writeCertAndKey(t, certFile, keyFile, tlsCert2)

	// Reload.
	if err := cm.ReloadCert(); err != nil {
		t.Fatalf("ReloadCert: %v", err)
	}

	cert2, _ := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "reload.test"})
	x2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if x1.SerialNumber.Cmp(x2.SerialNumber) == 0 {
		t.Error("cert serial unchanged after reload — expected new cert")
	}
}

func TestCertManager_TLSConfig_NextProtos(t *testing.T) {
	cm, err := NewCertManager("example.com", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	tc := cm.TLSConfig()
	if tc == nil {
		t.Fatal("TLSConfig returned nil")
	}
	if tc.GetCertificate == nil {
		t.Error("GetCertificate not set")
	}

	want := map[string]bool{"h2": true, "http/1.1": true, "acme-tls/1": true}
	for _, p := range tc.NextProtos {
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("missing NextProtos: %v", want)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS12)
	}
}

func TestCertManager_HTTPHandler_SelfSigned_Nil(t *testing.T) {
	cm, err := NewCertManager("example.com", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.HTTPHandler() != nil {
		t.Error("HTTPHandler should be nil for self-signed mode")
	}
}

func TestCertManager_HTTPHandler_AutoCert_NonNil(t *testing.T) {
	cm, err := NewCertManager("example.com", true, "test@example.com", t.TempDir(), "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.Mode() != "autocert" {
		t.Fatalf("mode = %q, want autocert", cm.Mode())
	}
	if cm.HTTPHandler() == nil {
		t.Error("HTTPHandler should be non-nil for autocert mode")
	}
}

func TestALPN_Detection(t *testing.T) {
	tests := []struct {
		name   string
		protos []string
		target string
		want   bool
	}{
		{"acme present", []string{"h2", "http/1.1", "acme-tls/1"}, "acme-tls/1", true},
		{"acme absent", []string{"h2", "http/1.1"}, "acme-tls/1", false},
		{"empty list", nil, "acme-tls/1", false},
		{"exact match", []string{"acme-tls/1"}, "acme-tls/1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsALPN(tt.protos, tt.target)
			if got != tt.want {
				t.Errorf("containsALPN(%v, %q) = %v, want %v", tt.protos, tt.target, got, tt.want)
			}
		})
	}
}

func TestParseALPN_FromRawClientHello(t *testing.T) {
	// Construct a minimal ClientHello with ALPN extension containing "acme-tls/1".
	// This tests the parseALPN function via parseClientHello.
	hello := buildMinimalClientHelloWithALPN([]string{"h2", "acme-tls/1"})
	chi, err := parseClientHello(hello)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if !containsALPN(chi.ALPNProtos, "acme-tls/1") {
		t.Errorf("ALPNProtos = %v, want to contain acme-tls/1", chi.ALPNProtos)
	}
	if !containsALPN(chi.ALPNProtos, "h2") {
		t.Errorf("ALPNProtos = %v, want to contain h2", chi.ALPNProtos)
	}
}

func TestParseALPN_NoExtensions(t *testing.T) {
	// Minimal ClientHello without extensions.
	hello := buildMinimalClientHello()
	chi, err := parseClientHello(hello)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if len(chi.ALPNProtos) != 0 {
		t.Errorf("ALPNProtos = %v, want empty", chi.ALPNProtos)
	}
}

// ---------- Helpers ----------

func writeCertAndKey(t *testing.T, certFile, keyFile string, cert tls.Certificate) {
	t.Helper()
	// Write cert PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Write key PEM.
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// buildMinimalClientHello constructs a bare-minimum TLS ClientHello record
// (no extensions) for testing parseClientHello.
func buildMinimalClientHello() []byte {
	// Record header: ContentType(1) + Version(2) + Length(2)
	// Handshake header: Type(1) + Length(3)
	// ClientVersion(2) + Random(32) + SessionID_len(1) + SessionID(0)
	// CipherSuites_len(2) + CipherSuites(2) + Compression_len(1) + Compression(1)
	var b []byte

	// Handshake body
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03) // ClientVersion TLS 1.2
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	body = append(body, random...)  // Random
	body = append(body, 0x00)       // SessionID length = 0
	body = append(body, 0x00, 0x02) // CipherSuites length = 2
	body = append(body, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0x01)       // Compression methods length = 1
	body = append(body, 0x00)       // null compression

	// Handshake header
	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// Record header
	b = append(b, 0x16)       // ContentType: Handshake
	b = append(b, 0x03, 0x01) // Version: TLS 1.0 (common in records)
	recordLen := len(handshake)
	b = append(b, byte(recordLen>>8), byte(recordLen))
	b = append(b, handshake...)

	return b
}

// buildMinimalClientHelloWithALPN constructs a TLS ClientHello with an ALPN extension.
func buildMinimalClientHelloWithALPN(protos []string) []byte {
	var b []byte

	// Build ALPN extension payload
	var alpnList []byte
	for _, p := range protos {
		alpnList = append(alpnList, byte(len(p)))
		alpnList = append(alpnList, []byte(p)...)
	}
	// ALPN extension: list_length(2) + list
	alpnPayload := make([]byte, 2+len(alpnList))
	alpnPayload[0] = byte(len(alpnList) >> 8)
	alpnPayload[1] = byte(len(alpnList))
	copy(alpnPayload[2:], alpnList)

	// Extension: type(2) + length(2) + payload
	ext := make([]byte, 0, 4+len(alpnPayload))
	ext = append(ext, 0x00, 0x10) // ALPN extension type
	ext = append(ext, byte(len(alpnPayload)>>8), byte(len(alpnPayload)))
	ext = append(ext, alpnPayload...)

	// Extensions block: length(2) + extensions
	extensions := make([]byte, 0, 2+len(ext))
	extensions = append(extensions, byte(len(ext)>>8), byte(len(ext)))
	extensions = append(extensions, ext...)

	// Handshake body
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03) // ClientVersion TLS 1.2
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 0x10)
	}
	body = append(body, random...)  // Random
	body = append(body, 0x00)       // SessionID length = 0
	body = append(body, 0x00, 0x02) // CipherSuites length = 2
	body = append(body, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0x01)       // Compression methods length = 1
	body = append(body, 0x00)       // null compression
	body = append(body, extensions...)

	// Handshake header
	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// Record header
	b = append(b, 0x16)       // ContentType: Handshake
	b = append(b, 0x03, 0x01) // Version: TLS 1.0
	recordLen := len(handshake)
	b = append(b, byte(recordLen>>8), byte(recordLen))
	b = append(b, handshake...)

	return b
}
