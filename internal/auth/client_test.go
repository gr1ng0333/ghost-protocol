package auth

import (
	"encoding/hex"
	"testing"
)

func TestNewClientAuth_Valid(t *testing.T) {
	client, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair (client): %v", err)
	}
	server, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair (server): %v", err)
	}

	ca, err := NewClientAuth(client.Private, server.Public)
	if err != nil {
		t.Fatalf("NewClientAuth: %v", err)
	}
	if ca == nil {
		t.Fatal("NewClientAuth returned nil")
	}
}

func TestNewClientAuth_ZeroServerKey(t *testing.T) {
	client, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}
	var zeroPub [32]byte
	_, err = NewClientAuth(client.Private, zeroPub)
	if err == nil {
		t.Fatal("expected error for zero server public key")
	}
}

func TestClientAuth_InjectSessionID(t *testing.T) {
	client, _ := GenKeyPair()
	server, _ := GenKeyPair()
	ca, err := NewClientAuth(client.Private, server.Public)
	if err != nil {
		t.Fatalf("NewClientAuth: %v", err)
	}

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	id1, err := ca.InjectSessionID(random)
	if err != nil {
		t.Fatalf("InjectSessionID: %v", err)
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(id1))
	}

	// Deterministic: same random → same result
	id2, err := ca.InjectSessionID(random)
	if err != nil {
		t.Fatalf("InjectSessionID (2nd call): %v", err)
	}
	if !bytesEqual(id1, id2) {
		t.Fatal("InjectSessionID not deterministic")
	}
}

func TestClientAuth_InjectSessionID_NilRandom(t *testing.T) {
	client, _ := GenKeyPair()
	server, _ := GenKeyPair()
	ca, _ := NewClientAuth(client.Private, server.Public)

	_, err := ca.InjectSessionID(nil)
	if err == nil {
		t.Fatal("expected error for nil random")
	}

	_, err = ca.InjectSessionID([]byte{})
	if err == nil {
		t.Fatal("expected error for empty random")
	}
}

func TestClientAuth_DeriveSessionToken(t *testing.T) {
	client, _ := GenKeyPair()
	server, _ := GenKeyPair()
	ca, _ := NewClientAuth(client.Private, server.Public)

	binding := []byte("test-binding-value")
	token, err := ca.DeriveSessionToken(binding)
	if err != nil {
		t.Fatalf("DeriveSessionToken: %v", err)
	}

	// Must be valid hex, 64 chars (32 bytes)
	decoded, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 decoded bytes, got %d", len(decoded))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
