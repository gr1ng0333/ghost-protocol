package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ghost/internal/auth"
)

// testHandlerSetup creates a ghostHandler and valid token for unit tests.
func testHandlerSetup(t *testing.T) (*ghostHandler, string) {
	t.Helper()
	serverKP, _ := auth.GenKeyPair()
	clientKP, _ := auth.GenKeyPair()
	sa, _ := auth.NewServerAuth(serverKP.Private, [][32]byte{clientKP.Public})
	sharedSecret, _ := auth.SharedSecret(clientKP.Private, serverKP.Public)
	binding := []byte("test-binding-value")
	handler := newGhostHandler(sa, sharedSecret, binding)
	token := auth.DeriveSessionToken(sharedSecret, binding)
	return handler, token
}

func TestGhostHandler_EchoPost(t *testing.T) {
	handler, token := testHandlerSetup(t)

	body := "hello"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader(body))
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}
	if got := rr.Body.String(); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestGhostHandler_MissingToken(t *testing.T) {
	handler, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_InvalidToken(t *testing.T) {
	handler, _ := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	req.Header.Set("X-Session-Token", "wrong-token-value")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_GetEndpoint(t *testing.T) {
	handler, token := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events/test", nil)
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}
	got, _ := io.ReadAll(rr.Body)
	if string(got) != "ghost-ok\n" {
		t.Errorf("body = %q, want %q", got, "ghost-ok\n")
	}
}

func TestGhostHandler_UnknownPath(t *testing.T) {
	handler, token := testHandlerSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
