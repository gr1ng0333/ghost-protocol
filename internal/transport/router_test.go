package transport

import (
	"testing"

	"ghost/internal/auth"
)

func TestConnRouter_AuthenticatedClient(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	sessionID := auth.ComputeSessionID(sharedSecret, random)

	r := newConnRouter(sa)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: sessionID,
	}

	mode, secret := r.route(chi)
	if mode != routeGhost {
		t.Errorf("route() = %d, want routeGhost (%d)", mode, routeGhost)
	}
	if secret != sharedSecret {
		t.Error("route() returned wrong shared secret")
	}
}

func TestConnRouter_WrongSessionID(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	badSessionID := make([]byte, 32)
	for i := range badSessionID {
		badSessionID[i] = 0xFF
	}

	r := newConnRouter(sa)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: badSessionID,
	}

	mode, _ := r.route(chi)
	if mode != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", mode, routeFallback)
	}
}

func TestConnRouter_EmptySessionID(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	random := make([]byte, 32)

	r := newConnRouter(sa)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: nil,
	}

	mode, _ := r.route(chi)
	if mode != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", mode, routeFallback)
	}
}

func TestConnRouter_ShortRandom(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	r := newConnRouter(sa)
	chi := &clientHelloInfo{
		Random:    []byte{0x01, 0x02, 0x03},
		SessionID: make([]byte, 32),
	}

	mode, _ := r.route(chi)
	if mode != routeFallback {
		t.Errorf("route() = %d, want routeFallback (%d)", mode, routeFallback)
	}
}

func TestConnRouter_NilClientHelloInfo(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	r := newConnRouter(sa)

	mode, _ := r.route(nil)
	if mode != routeFallback {
		t.Errorf("route(nil) = %d, want routeFallback (%d)", mode, routeFallback)
	}
}

func TestConnRouter_Deterministic(t *testing.T) {
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})

	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 7)
	}
	sessionID := auth.ComputeSessionID(sharedSecret, random)

	r := newConnRouter(sa)
	chi := &clientHelloInfo{
		Random:    random,
		SessionID: sessionID,
	}

	for i := 0; i < 100; i++ {
		mode, _ := r.route(chi)
		if mode != routeGhost {
			t.Fatalf("route() returned routeFallback on iteration %d", i)
		}
	}
}
