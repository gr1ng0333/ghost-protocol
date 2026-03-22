package auth

import (
	"testing"
)

func TestNewServerAuth_Valid(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	sa, err := NewServerAuth(server.Private, [][32]byte{client.Public})
	if err != nil {
		t.Fatalf("NewServerAuth: %v", err)
	}
	if sa == nil {
		t.Fatal("NewServerAuth returned nil")
	}
}

func TestNewServerAuth_NoClients(t *testing.T) {
	server, _ := GenKeyPair()

	sa, err := NewServerAuth(server.Private, nil)
	if err != nil {
		t.Fatalf("NewServerAuth with nil clients: %v", err)
	}
	if sa == nil {
		t.Fatal("NewServerAuth returned nil for empty client list")
	}

	sa2, err := NewServerAuth(server.Private, [][32]byte{})
	if err != nil {
		t.Fatalf("NewServerAuth with empty clients: %v", err)
	}
	if sa2 == nil {
		t.Fatal("NewServerAuth returned nil for empty slice")
	}
}

func TestServerAuth_VerifySessionID_Valid(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	ca, _ := NewClientAuth(client.Private, server.Public)
	sa, _ := NewServerAuth(server.Private, [][32]byte{client.Public})

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 10)
	}

	sessionID, _ := ca.InjectSessionID(random)

	secret, ok := sa.VerifySessionID(random, sessionID)
	if !ok {
		t.Fatal("VerifySessionID returned false for valid session ID")
	}

	// The returned shared secret should be the same one the client used
	expectedSecret, _ := SharedSecret(client.Private, server.Public)
	if secret != expectedSecret {
		t.Fatal("returned shared secret does not match expected")
	}
}

func TestServerAuth_VerifySessionID_Invalid(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	sa, _ := NewServerAuth(server.Private, [][32]byte{client.Public})

	random := make([]byte, 32)
	wrongID := make([]byte, 32)

	_, ok := sa.VerifySessionID(random, wrongID)
	if ok {
		t.Fatal("VerifySessionID returned true for invalid session ID")
	}
}

func TestServerAuth_VerifySessionID_MultipleClients(t *testing.T) {
	server, _ := GenKeyPair()
	c1, _ := GenKeyPair()
	c2, _ := GenKeyPair()
	c3, _ := GenKeyPair()

	sa, _ := NewServerAuth(server.Private, [][32]byte{c1.Public, c2.Public, c3.Public})

	// Client 2 authenticates
	ca2, _ := NewClientAuth(c2.Private, server.Public)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 42)
	}
	sessionID, _ := ca2.InjectSessionID(random)

	secret, ok := sa.VerifySessionID(random, sessionID)
	if !ok {
		t.Fatal("VerifySessionID failed to identify client 2")
	}

	// Verify it's client 2's shared secret
	expected, _ := SharedSecret(c2.Private, server.Public)
	if secret != expected {
		t.Fatal("returned shared secret does not match client 2")
	}

	// Client 1 should also work
	ca1, _ := NewClientAuth(c1.Private, server.Public)
	sessionID1, _ := ca1.InjectSessionID(random)
	secret1, ok := sa.VerifySessionID(random, sessionID1)
	if !ok {
		t.Fatal("VerifySessionID failed to identify client 1")
	}
	expected1, _ := SharedSecret(c1.Private, server.Public)
	if secret1 != expected1 {
		t.Fatal("returned shared secret does not match client 1")
	}

	// Unknown client should fail
	unknown, _ := GenKeyPair()
	caU, _ := NewClientAuth(unknown.Private, server.Public)
	sessionIDU, _ := caU.InjectSessionID(random)
	_, ok = sa.VerifySessionID(random, sessionIDU)
	if ok {
		t.Fatal("VerifySessionID accepted unknown client")
	}
}

func TestServerAuth_VerifyToken_Valid(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	sa, _ := NewServerAuth(server.Private, [][32]byte{client.Public})
	secret, _ := SharedSecret(client.Private, server.Public)
	binding := []byte("tls-binding")

	token := DeriveSessionToken(secret, binding)
	if !sa.VerifyToken(secret, binding, token) {
		t.Fatal("VerifyToken returned false for valid token")
	}
}

func TestServerAuth_VerifyToken_Invalid(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	sa, _ := NewServerAuth(server.Private, [][32]byte{client.Public})
	secret, _ := SharedSecret(client.Private, server.Public)
	binding := []byte("tls-binding")

	wrong := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if sa.VerifyToken(secret, binding, wrong) {
		t.Fatal("VerifyToken returned true for wrong token")
	}
}

func TestServerAuth_VerifyToken_MalformedHex(t *testing.T) {
	server, _ := GenKeyPair()
	client, _ := GenKeyPair()

	sa, _ := NewServerAuth(server.Private, [][32]byte{client.Public})
	secret, _ := SharedSecret(client.Private, server.Public)
	binding := []byte("tls-binding")

	if sa.VerifyToken(secret, binding, "not-hex!!") {
		t.Fatal("VerifyToken accepted malformed hex")
	}
	if sa.VerifyToken(secret, binding, "") {
		t.Fatal("VerifyToken accepted empty token")
	}
}

func TestAuth_FullFlow(t *testing.T) {
	// 1. Generate key pairs
	server, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair (server): %v", err)
	}
	client, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair (client): %v", err)
	}

	// 2. Create client and server auth
	ca, err := NewClientAuth(client.Private, server.Public)
	if err != nil {
		t.Fatalf("NewClientAuth: %v", err)
	}
	sa, err := NewServerAuth(server.Private, [][32]byte{client.Public})
	if err != nil {
		t.Fatalf("NewServerAuth: %v", err)
	}

	// 3. Client: inject session ID into ClientHello
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 3)
	}
	sessionID, err := ca.InjectSessionID(random)
	if err != nil {
		t.Fatalf("InjectSessionID: %v", err)
	}
	if len(sessionID) != 32 {
		t.Fatalf("sessionID length: got %d, want 32", len(sessionID))
	}

	// 4. Server: verify session ID
	sharedSecret, ok := sa.VerifySessionID(random, sessionID)
	if !ok {
		t.Fatal("server failed to verify client session ID")
	}

	// 5. Client: derive session token (post-handshake, for HTTP/2)
	binding := []byte("exported-keying-material-for-test")
	token, err := ca.DeriveSessionToken(binding)
	if err != nil {
		t.Fatalf("DeriveSessionToken: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("token length: got %d, want 64", len(token))
	}

	// 6. Server: verify token
	if !sa.VerifyToken(sharedSecret, binding, token) {
		t.Fatal("server failed to verify client session token")
	}

	// 7. Negative: wrong binding should fail
	if sa.VerifyToken(sharedSecret, []byte("wrong-binding"), token) {
		t.Fatal("server accepted token with wrong binding")
	}
}
