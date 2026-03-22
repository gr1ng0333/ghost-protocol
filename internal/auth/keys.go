package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair holds a curve25519 key pair for x25519 key exchange.
type KeyPair struct {
	Public  [32]byte
	Private [32]byte
}

// GenKeyPair generates a new x25519 key pair using crypto/rand.
// The private key is generated randomly, and the public key is
// derived using x25519 scalar base multiplication.
func GenKeyPair() (*KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("auth.GenKeyPair: %w", err)
	}
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("auth.GenKeyPair: %w", err)
	}
	copy(kp.Public[:], pub)
	return &kp, nil
}

// SharedSecret computes the x25519 shared secret from our private
// key and the peer's public key. Returns error if the result is
// all zeros (low-order point).
func SharedSecret(priv, peerPub [32]byte) ([32]byte, error) {
	var secret [32]byte
	raw, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return secret, fmt.Errorf("auth.SharedSecret: %w", err)
	}
	copy(secret[:], raw)

	var zero [32]byte
	if subtle.ConstantTimeCompare(secret[:], zero[:]) == 1 {
		return secret, errors.New("auth.SharedSecret: result is all zeros (low-order point)")
	}
	return secret, nil
}

// ComputeSessionID returns HMAC-SHA256(sharedSecret, random)[:32].
// This is the full 32-byte HMAC output used as TLS ClientHello SessionID.
// random is the 32-byte ClientHello.Random value.
func ComputeSessionID(sharedSecret [32]byte, random []byte) []byte {
	mac := hmac.New(sha256.New, sharedSecret[:])
	mac.Write(random)
	return mac.Sum(nil)
}

// VerifySessionID checks whether sessionID matches the expected value
// for the given sharedSecret and random. Uses constant-time comparison.
func VerifySessionID(sharedSecret [32]byte, random, sessionID []byte) bool {
	expected := ComputeSessionID(sharedSecret, random)
	return subtle.ConstantTimeCompare(expected, sessionID) == 1
}

// DeriveSessionToken computes HMAC-SHA256(sharedSecret, "ghost-session" + binding)
// and returns it as a hex-encoded string for use as an HTTP header value.
// binding is a channel-binding value from the TLS connection (e.g., tls_unique
// or exported keying material).
func DeriveSessionToken(sharedSecret [32]byte, binding []byte) string {
	mac := hmac.New(sha256.New, sharedSecret[:])
	mac.Write([]byte("ghost-session"))
	mac.Write(binding)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySessionToken checks the hex-encoded token against the expected value.
// Uses constant-time comparison after decoding.
func VerifySessionToken(sharedSecret [32]byte, binding []byte, token string) bool {
	decoded, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, sharedSecret[:])
	mac.Write([]byte("ghost-session"))
	mac.Write(binding)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(expected, decoded) == 1
}
