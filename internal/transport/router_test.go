package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// computeValidSessionID produces a valid HMAC-SHA256(secret, random)[:32] for testing.
func computeValidSessionID(secret, random []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(random)
	return mac.Sum(nil)[:32]
}

func TestConnRouter_AuthenticatedClient(t *testing.T) {
	secret := []byte("ghost-shared-secret")
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	sessionID := computeValidSessionID(secret, random)

	r := newConnRouter(secret)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: sessionID,
	}

	if got := r.route(chi); got != routeGhost {
		t.Errorf("route() = %d, want routeGhost (%d)", got, routeGhost)
	}
}

func TestConnRouter_WrongSessionID(t *testing.T) {
	secret := []byte("ghost-shared-secret")
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	// Wrong session ID — just random bytes.
	badSessionID := make([]byte, 32)
	for i := range badSessionID {
		badSessionID[i] = 0xFF
	}

	r := newConnRouter(secret)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: badSessionID,
	}

	if got := r.route(chi); got != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", got, routeFallback)
	}
}

func TestConnRouter_EmptySessionID(t *testing.T) {
	secret := []byte("ghost-shared-secret")
	random := make([]byte, 32)

	r := newConnRouter(secret)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: nil,
	}

	if got := r.route(chi); got != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", got, routeFallback)
	}
}

func TestConnRouter_ShortRandom(t *testing.T) {
	secret := []byte("ghost-shared-secret")

	r := newConnRouter(secret)
	chi := &clientHelloInfo{
		Random:    []byte{0x01, 0x02, 0x03}, // Only 3 bytes
		SessionID: make([]byte, 32),
	}

	if got := r.route(chi); got != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", got, routeFallback)
	}
}

func TestConnRouter_NilClientHelloInfo(t *testing.T) {
	secret := []byte("ghost-shared-secret")
	r := newConnRouter(secret)

	if got := r.route(nil); got != routeFallback {
		t.Errorf("route(nil) = %d, want routeFallback (%d)", got, routeFallback)
	}
}

func TestCheckSessionID_Deterministic(t *testing.T) {
	secret := []byte("determinism-test-secret")
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 7)
	}
	sessionID := computeValidSessionID(secret, random)

	// Call multiple times — must always return true.
	for i := 0; i < 100; i++ {
		if !checkSessionID(random, sessionID, secret) {
			t.Fatalf("checkSessionID returned false on iteration %d", i)
		}
	}
}
