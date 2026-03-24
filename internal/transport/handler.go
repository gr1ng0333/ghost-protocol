package transport

import (
	"ghost/internal/auth"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// ghostHandler handles HTTP/2 requests for an authenticated Ghost session.
// POST requests carry upstream Ghost frames (client → server mux).
// GET requests open a long-poll for downstream frames (server mux → client).
type ghostHandler struct {
	serverAuth   auth.ServerAuth
	sharedSecret [32]byte
	binding      []byte // TLS channel binding for token verification

	upW   *io.PipeWriter // POST bodies written here → mux decoder
	downR *io.PipeReader // mux encoder writes here → GET response

	uploadPath   string // expected POST path
	downloadPath string // expected GET path

	sessionMgr *SessionManager // optional session lifecycle manager
	sessionID  string          // session ID for touch tracking
}

// newGhostHandler creates an HTTP/2 handler wired to the mux pipes.
// upW feeds POST bodies to the ServerMux decoder.
// downR streams ServerMux encoder output to GET long-poll responses.
func newGhostHandler(sa auth.ServerAuth, secret [32]byte, binding []byte, upW *io.PipeWriter, downR *io.PipeReader, uploadPath, downloadPath string) *ghostHandler {
	return &ghostHandler{
		serverAuth:   sa,
		sharedSecret: secret,
		binding:      binding,
		upW:          upW,
		downR:        downR,
		uploadPath:   uploadPath,
		downloadPath: downloadPath,
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

	// Touch session on each HTTP activity.
	if h.sessionMgr != nil {
		h.sessionMgr.Touch(h.sessionID)
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost copies the POST request body into the upstream pipe,
// which feeds the ServerMux decoder with Ghost frames.
func (h *ghostHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	_, err := io.Copy(h.upW, r.Body)
	if err != nil {
		slog.Warn("ghost: POST body copy", "err", err, "remote", r.RemoteAddr)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleGet opens a long-poll response that streams downstream Ghost frames
// from the ServerMux encoder to the client.
func (h *ghostHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	buf := make([]byte, 32*1024)
	for {
		n, err := h.downR.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // client disconnected
			}
			flusher.Flush()
		}
		if err != nil {
			return // pipe closed or error
		}
	}
}
