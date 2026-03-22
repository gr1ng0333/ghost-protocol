package auth

import (
	"errors"
	"fmt"
)

// ClientAuth handles client-side authentication during TLS handshake.
type ClientAuth interface {
	// InjectSessionID returns the 32-byte SessionID value to embed
	// in the TLS ClientHello. This is derived from the shared secret
	// and the ClientHello.Random.
	InjectSessionID(random []byte) ([]byte, error)

	// DeriveSessionToken derives a session token from the TLS connection
	// for use in subsequent HTTP/2 requests.
	// binding is a channel-binding value from the TLS connection.
	DeriveSessionToken(binding []byte) (string, error)
}

// clientAuth implements ClientAuth for a single client identity.
type clientAuth struct {
	sharedSecret [32]byte
}

// NewClientAuth creates a ClientAuth from the client's private key
// and the server's public key. It computes the shared secret internally.
func NewClientAuth(clientPriv, serverPub [32]byte) (ClientAuth, error) {
	secret, err := SharedSecret(clientPriv, serverPub)
	if err != nil {
		return nil, fmt.Errorf("auth.ClientAuth.New: %w", err)
	}
	return &clientAuth{sharedSecret: secret}, nil
}

// InjectSessionID computes HMAC-SHA256(sharedSecret, random)[:32].
// The caller will set this as the TLS ClientHello SessionID.
func (c *clientAuth) InjectSessionID(random []byte) ([]byte, error) {
	if len(random) == 0 {
		return nil, errors.New("auth.ClientAuth.InjectSessionID: random must not be nil or empty")
	}
	return ComputeSessionID(c.sharedSecret, random), nil
}

// DeriveSessionToken computes the session token from the channel binding.
func (c *clientAuth) DeriveSessionToken(binding []byte) (string, error) {
	return deriveToken(c.sharedSecret, binding), nil
}

// deriveToken is a package-internal wrapper to call the package-level
// DeriveSessionToken without name collision on the method.
func deriveToken(secret [32]byte, binding []byte) string {
	return DeriveSessionToken(secret, binding)
}
