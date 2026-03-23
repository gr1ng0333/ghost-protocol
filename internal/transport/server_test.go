package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
)

// buildClientHello constructs a minimal TLS ClientHello for testing.
func buildClientHello(random []byte, sessionID []byte) []byte {
	// Handshake body: ClientVersion(2) + Random(32) + SessionIDLen(1) + SessionID(n)
	handshakeBody := make([]byte, 0, 2+32+1+len(sessionID))
	handshakeBody = append(handshakeBody, 0x03, 0x03) // ClientVersion TLS 1.2
	handshakeBody = append(handshakeBody, random...)
	handshakeBody = append(handshakeBody, byte(len(sessionID)))
	handshakeBody = append(handshakeBody, sessionID...)

	// Handshake header: Type(1) + Length(3)
	handshakeLen := len(handshakeBody)
	handshake := make([]byte, 0, 4+handshakeLen)
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	handshake = append(handshake, handshakeBody...)

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 compat
	recordLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recordLen, uint16(len(handshake)))
	record = append(record, recordLen...)
	record = append(record, handshake...)

	return record
}

func TestParseClientHello_Valid(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(0x80 | i)
	}

	raw := buildClientHello(random, sessionID)
	chi, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	if !bytes.Equal(chi.Random, random) {
		t.Errorf("Random mismatch:\n got  %x\n want %x", chi.Random, random)
	}
	if !bytes.Equal(chi.SessionID, sessionID) {
		t.Errorf("SessionID mismatch:\n got  %x\n want %x", chi.SessionID, sessionID)
	}
	if !bytes.Equal(chi.Raw, raw) {
		t.Error("Raw should equal the input bytes")
	}
}

func TestParseClientHello_TooShort(t *testing.T) {
	_, err := parseClientHello([]byte{0x16, 0x03, 0x01})
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestParseClientHello_WrongContentType(t *testing.T) {
	random := make([]byte, 32)
	raw := buildClientHello(random, nil)
	raw[0] = 0x15 // Change content type to Alert

	_, err := parseClientHello(raw)
	if err == nil {
		t.Fatal("expected error for wrong content type")
	}
}

func TestParseClientHello_WrongHandshakeType(t *testing.T) {
	random := make([]byte, 32)
	raw := buildClientHello(random, nil)
	raw[5] = 0x02 // Change to ServerHello

	_, err := parseClientHello(raw)
	if err == nil {
		t.Fatal("expected error for wrong handshake type")
	}
}

func TestPeekConn_ReplayBytes(t *testing.T) {
	// Create a pipe to simulate a connection.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("HELLO, WORLD! This is additional data beyond the peek.")

	// Write in a goroutine since Pipe is synchronous.
	go func() {
		client.Write(payload)
		client.Close()
	}()

	pc, peeked, err := newPeekConn(server, 5)
	if err != nil {
		t.Fatalf("newPeekConn: %v", err)
	}

	if !bytes.Equal(peeked, payload[:5]) {
		t.Fatalf("peeked = %q, want %q", peeked, payload[:5])
	}

	// Now read everything from peekConn — should get the full payload.
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("ReadAll mismatch:\n got  %q\n want %q", got, payload)
	}
}

func TestPeekConn_PreservesConnMethods(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		server.Write([]byte("data"))
	}()

	pc, _, err := newPeekConn(client, 4)
	if err != nil {
		t.Fatalf("newPeekConn: %v", err)
	}
	defer pc.Close()

	if pc.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil")
	}
	if pc.RemoteAddr() == nil {
		t.Error("RemoteAddr() returned nil")
	}
}

func TestNewServer_ListenAndClose(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Domain: "test.example.com",
	}

	cert, err := GenerateSelfSignedCert("test.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	srv := NewServer(cfg, cert, sa, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0", "127.0.0.1:8080")
	}()

	// Wait briefly for the listener to start.
	time.Sleep(100 * time.Millisecond)

	// Connect with raw TCP to verify it accepts connections.
	gs := srv.(*ghostServer)
	gs.mu.Lock()
	addr := gs.listener.Addr().String()
	gs.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("TCP dial to server: %v", err)
	}

	// Send a minimal TLS ClientHello so the server can parse it.
	random := make([]byte, 32)
	sessionID := make([]byte, 32)
	hello := buildClientHello(random, sessionID)
	conn.Write(hello)

	// Read until server closes the connection (handleConn is a placeholder that closes).
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Log("server sent unexpected data")
	}
	conn.Close()

	// Graceful shutdown.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert("ghost.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate data")
	}
	if cert.PrivateKey == nil {
		t.Fatal("no private key")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if x509Cert.Subject.CommonName != "ghost.example.com" {
		t.Errorf("CN = %q, want %q", x509Cert.Subject.CommonName, "ghost.example.com")
	}

	foundDNS := false
	for _, name := range x509Cert.DNSNames {
		if name == "ghost.example.com" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Errorf("DNSNames = %v, want to contain %q", x509Cert.DNSNames, "ghost.example.com")
	}

	if x509Cert.NotAfter.Before(time.Now().Add(364 * 24 * time.Hour)) {
		t.Errorf("certificate expires too soon: %v", x509Cert.NotAfter)
	}
}
