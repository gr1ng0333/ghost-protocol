package transport

import (
	"ghost/internal/auth"
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
	serverAuth auth.ServerAuth
}

// newConnRouter creates a router with the given ServerAuth.
func newConnRouter(sa auth.ServerAuth) *connRouter {
	return &connRouter{serverAuth: sa}
}

// route inspects the parsed ClientHello and returns the routing decision
// along with the shared secret for authenticated clients.
// It always checks all client keys to avoid timing side-channels.
func (r *connRouter) route(chi *clientHelloInfo) (routeMode, [32]byte) {
	var zero [32]byte
	if chi == nil || r.serverAuth == nil {
		return routeFallback, zero
	}
	secret, ok := r.serverAuth.VerifySessionID(chi.Random, chi.SessionID)
	if ok {
		return routeGhost, secret
	}
	return routeFallback, zero
}
