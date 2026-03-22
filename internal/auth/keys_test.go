package auth

import (
	"encoding/hex"
	"testing"
)

func TestGenKeyPair(t *testing.T) {
	kp1, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair() error: %v", err)
	}
	kp2, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair() error: %v", err)
	}

	// Keys must be 32 bytes (guaranteed by type, but verify non-zero)
	var zero [32]byte
	if kp1.Public == zero {
		t.Fatal("public key is all zeros")
	}
	if kp1.Private == zero {
		t.Fatal("private key is all zeros")
	}

	// Two calls must produce different keys
	if kp1.Public == kp2.Public {
		t.Fatal("two GenKeyPair calls produced identical public keys")
	}
	if kp1.Private == kp2.Private {
		t.Fatal("two GenKeyPair calls produced identical private keys")
	}
}

func TestSharedSecret_Symmetric(t *testing.T) {
	a, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}
	b, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	ab, err := SharedSecret(a.Private, b.Public)
	if err != nil {
		t.Fatalf("SharedSecret(a,b): %v", err)
	}
	ba, err := SharedSecret(b.Private, a.Public)
	if err != nil {
		t.Fatalf("SharedSecret(b,a): %v", err)
	}

	if ab != ba {
		t.Fatalf("SharedSecret not symmetric:\n  ab=%x\n  ba=%x", ab, ba)
	}
}

func TestSharedSecret_ZeroPointRejected(t *testing.T) {
	kp, err := GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}
	var zeroPub [32]byte
	_, err = SharedSecret(kp.Private, zeroPub)
	if err == nil {
		t.Fatal("SharedSecret with zero public key should return error")
	}
}

func TestComputeSessionID_Deterministic(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	random := []byte("random-value-32-bytes-long-xxxx")

	id1 := ComputeSessionID(secret, random)
	id2 := ComputeSessionID(secret, random)

	if !equal(id1, id2) {
		t.Fatalf("not deterministic:\n  %x\n  %x", id1, id2)
	}
}

func TestComputeSessionID_DifferentRandoms(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))

	id1 := ComputeSessionID(secret, []byte("random-A"))
	id2 := ComputeSessionID(secret, []byte("random-B"))

	if equal(id1, id2) {
		t.Fatal("different randoms produced identical session IDs")
	}
}

func TestComputeSessionID_Length(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	id := ComputeSessionID(secret, []byte("some-random"))

	if len(id) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(id))
	}
}

func TestVerifySessionID_Valid(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	random := []byte("random-value")

	id := ComputeSessionID(secret, random)
	if !VerifySessionID(secret, random, id) {
		t.Fatal("VerifySessionID returned false for valid ID")
	}
}

func TestVerifySessionID_Invalid(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	random := []byte("random-value")

	wrongID := make([]byte, 32)
	if VerifySessionID(secret, random, wrongID) {
		t.Fatal("VerifySessionID returned true for wrong ID")
	}
}

func TestVerifySessionID_WrongRandom(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))

	id := ComputeSessionID(secret, []byte("correct-random"))
	if VerifySessionID(secret, []byte("wrong-random"), id) {
		t.Fatal("VerifySessionID returned true for wrong random")
	}
}

func TestDeriveSessionToken_Roundtrip(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	binding := []byte("tls-binding-data")

	token := DeriveSessionToken(secret, binding)
	if !VerifySessionToken(secret, binding, token) {
		t.Fatal("VerifySessionToken returned false for valid token")
	}
}

func TestDeriveSessionToken_HexEncoded(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	binding := []byte("tls-binding-data")

	token := DeriveSessionToken(secret, binding)

	// Must be valid hex
	decoded, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}

	// 32 bytes hex-encoded = 64 characters
	if len(token) != 64 {
		t.Fatalf("expected token length 64, got %d", len(token))
	}
	if len(decoded) != 32 {
		t.Fatalf("expected decoded length 32, got %d", len(decoded))
	}
}

func TestVerifySessionToken_Invalid(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	binding := []byte("tls-binding-data")

	wrongToken := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if VerifySessionToken(secret, binding, wrongToken) {
		t.Fatal("VerifySessionToken returned true for wrong token")
	}
}

func TestVerifySessionToken_MalformedHex(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))
	binding := []byte("tls-binding-data")

	// Should return false without panicking
	if VerifySessionToken(secret, binding, "not-hex-at-all!!") {
		t.Fatal("VerifySessionToken returned true for malformed hex")
	}
	if VerifySessionToken(secret, binding, "") {
		t.Fatal("VerifySessionToken returned true for empty string")
	}
	if VerifySessionToken(secret, binding, "zzzz") {
		t.Fatal("VerifySessionToken returned true for invalid hex chars")
	}
}

func TestComputeSessionID_NilRandom(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("test-secret-32-bytes-long-xxxxx"))

	// nil random should not panic and produce valid output
	id := ComputeSessionID(secret, nil)
	if len(id) != 32 {
		t.Fatalf("expected 32 bytes for nil random, got %d", len(id))
	}

	// empty slice should behave the same as nil
	id2 := ComputeSessionID(secret, []byte{})
	if !equal(id, id2) {
		t.Fatal("nil and empty random produced different results")
	}
}

func equal(a, b []byte) bool {
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
