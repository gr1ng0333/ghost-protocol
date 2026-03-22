package transport

import (
	"crypto/hmac"
	"crypto/sha256"
)

// routeMode indicates the routing decision for a connection.
type routeMode int

const (
	routeGhost    routeMode = iota // Authenticated Ghost client
	routeFallback                  // Unauthenticated → forward to Caddy
)

// connRouter decides how to handle incoming connections based on
// ClientHello authentication.
type connRouter struct {
	secret []byte // Shared secret for HMAC verification
}

// newConnRouter creates a router with the given shared secret.
func newConnRouter(secret []byte) *connRouter {
	return &connRouter{secret: secret}
}

// route inspects the parsed ClientHello and returns the routing decision.
// Authentication check: compute HMAC-SHA256(secret, random)[:32] and compare
// to the presented sessionID. If they match → routeGhost. Otherwise → routeFallback.
func (r *connRouter) route(chi *clientHelloInfo) routeMode {
	if chi == nil {
		return routeFallback
	}
	if checkSessionID(chi.Random, chi.SessionID, r.secret) {
		return routeGhost
	}
	return routeFallback
}

// checkSessionID verifies that sessionID matches HMAC-SHA256(secret, random)[:32].
func checkSessionID(random, sessionID, secret []byte) bool {
	if len(random) < 32 || len(sessionID) < 32 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(random)
	expected := mac.Sum(nil)[:32]
	return hmac.Equal(sessionID[:32], expected)
}
