package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ghost/internal/auth"
)

// testHandlerSetup creates a ghostHandler wired to io.Pipes and a valid token.
// Returns the handler, token, the read end of the upstream pipe (what POST writes),
// and the write end of the downstream pipe (what GET reads from).
func testHandlerSetup(t *testing.T) (handler *ghostHandler, token string, upR *io.PipeReader, downW *io.PipeWriter) {
	t.Helper()
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	binding := []byte("test-binding-value")

	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	t.Cleanup(func() {
		upR.Close()
		upW.Close()
		downR.Close()
		downW.Close()
	})

	handler = newGhostHandler(sa, sharedSecret, binding, upW, downR, "/api/upload", "/api/download")
	token = auth.DeriveSessionToken(sharedSecret, binding)
	return
}

func TestGhostHandler_Post(t *testing.T) {
	handler, token, upR, _ := testHandlerSetup(t)

	body := "hello"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader(body))
	req.Header.Set("X-Session-Token", token)

	// Drain upstream pipe in background so io.Copy in handler doesn't block.
	received := make(chan string, 1)
	go func() {
		buf := make([]byte, len(body))
		io.ReadFull(upR, buf)
		received <- string(buf)
	}()

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	got := <-received
	if got != body {
		t.Errorf("upstream pipe received %q, want %q", got, body)
	}
}

func TestGhostHandler_MissingToken(t *testing.T) {
	handler, _, _, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_InvalidToken(t *testing.T) {
	handler, _, _, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	req.Header.Set("X-Session-Token", "wrong-token-value")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_GetEndpoint(t *testing.T) {
	handler, token, _, downW := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events/test", nil)
	req.Header.Set("X-Session-Token", token)

	// Feed downstream data then close pipe so handler's read loop exits.
	go func() {
		downW.Write([]byte("downstream-data"))
		downW.Close()
	}()

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "downstream-data" {
		t.Errorf("body = %q, want %q", got, "downstream-data")
	}
}

func TestGhostHandler_UnknownPath(t *testing.T) {
	handler, token, _, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
