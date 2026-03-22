package transport

import (
	"ghost/internal/auth"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// ghostHandler handles HTTP/2 requests from authenticated Ghost clients.
// For Stage 2.2, this is an echo handler — real frame processing comes in Stage 2.3c.
type ghostHandler struct {
	serverAuth   auth.ServerAuth
	sharedSecret [32]byte
	binding      []byte // TLS channel binding for token verification
}

// newGhostHandler creates an HTTP/2 handler with the ServerAuth,
// per-client shared secret, and TLS channel binding for X-Session-Token validation.
func newGhostHandler(sa auth.ServerAuth, secret [32]byte, binding []byte) *ghostHandler {
	return &ghostHandler{
		serverAuth:   sa,
		sharedSecret: secret,
		binding:      binding,
	}
}

// ServeHTTP implements http.Handler.
func (h *ghostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate X-Session-Token on every request.
	token := r.Header.Get("X-Session-Token")
	if token == "" || !h.serverAuth.VerifyToken(h.sharedSecret, h.binding, token) {
		slog.Warn("ghost: invalid session token", "remote", r.RemoteAddr, "path", r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Route by method and path.
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodGet:
		h.handleGet(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handlePost echoes the request body back as the response.
func (h *ghostHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Warn("ghost: read POST body", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// handleGet writes a small acknowledgment response.
func (h *ghostHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ghost-ok\n"))
}
