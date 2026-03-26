package transport

import (
	"ghost/internal/auth"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ghostHandler handles HTTP/2 requests for an authenticated Ghost session.
// POST requests carry upstream Ghost frames (client → server mux).
// GET requests open a long-poll for downstream frames (server mux → client).
type ghostHandler struct {
	serverAuth   auth.ServerAuth
	sharedSecret [32]byte
	binding      []byte // TLS channel binding for token verification

	upW   *io.PipeWriter // POST bodies written here → mux decoder
	downR io.Reader      // mux encoder writes here → GET response

	uploadPath       string // expected POST path (per-frame)
	downloadPath     string // expected GET path (streaming)
	streamUploadPath string // streaming POST path (long-lived)

	sessionMgr *SessionManager // optional session lifecycle manager
	sessionID  string          // session ID for touch tracking
}

// newGhostHandler creates an HTTP/2 handler wired to the mux pipes.
// upW feeds POST bodies to the ServerMux decoder.
// downR streams ServerMux encoder output to GET long-poll responses.
func newGhostHandler(sa auth.ServerAuth, secret [32]byte, binding []byte, upW *io.PipeWriter, downR io.Reader, uploadPath, downloadPath, streamUploadPath string) *ghostHandler {
	return &ghostHandler{
		serverAuth:       sa,
		sharedSecret:     secret,
		binding:          binding,
		upW:              upW,
		downR:            downR,
		uploadPath:       uploadPath,
		downloadPath:     downloadPath,
		streamUploadPath: streamUploadPath,
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

	// Route by method and derived path.
	switch {
	case r.Method == http.MethodPost && r.URL.Path == h.streamUploadPath:
		h.handleStreamUpload(w, r)
	case r.Method == http.MethodPost && r.URL.Path == h.uploadPath:
		h.handlePost(w, r)
	case r.Method == http.MethodGet && r.URL.Path == h.downloadPath:
		h.handleGet(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleStreamUpload handles a long-lived POST where the client streams
// Ghost frames continuously through the request body. The server responds
// with 200 OK immediately and then reads frames from the body until the
// client closes the stream.
func (h *ghostHandler) handleStreamUpload(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Respond immediately so the client's RoundTrip returns.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Read frames from request body until the client closes the stream.
	_, err := io.Copy(h.upW, r.Body)
	if err != nil {
		slog.Warn("ghost: stream upload ended", "err", err, "remote", r.RemoteAddr)
	}
}

// handlePost copies the POST request body into the upstream pipe,
// which feeds the ServerMux decoder with Ghost frames.
// Body is limited to 65536 bytes to prevent memory exhaustion from oversized requests.
func (h *ghostHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	_, err := io.Copy(h.upW, io.LimitReader(r.Body, 65536))
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

	// Flush goroutine: flushes at most every 5ms for batching.
	flushMu := &sync.Mutex{}
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				flushMu.Lock()
				flusher.Flush()
				flushMu.Unlock()
			}
		}
	}()

	for {
		n, err := h.downR.Read(buf)
		if n > 0 {
			flushMu.Lock()
			_, werr := w.Write(buf[:n])
			flushMu.Unlock()
			if werr != nil {
				return // client disconnected
			}
		}
		if err != nil {
			return // pipe closed or error
		}
	}
}
