package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGhostHandler_EchoPost(t *testing.T) {
	secret := []byte("test-secret")
	handler := newGhostHandler(secret)
	token := computeSessionToken(secret)

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
	secret := []byte("test-secret")
	handler := newGhostHandler(secret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_InvalidToken(t *testing.T) {
	secret := []byte("test-secret")
	handler := newGhostHandler(secret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("hello"))
	req.Header.Set("X-Session-Token", "wrong-token-value")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGhostHandler_GetEndpoint(t *testing.T) {
	secret := []byte("test-secret")
	handler := newGhostHandler(secret)
	token := computeSessionToken(secret)

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
	secret := []byte("test-secret")
	handler := newGhostHandler(secret)
	token := computeSessionToken(secret)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	req.Header.Set("X-Session-Token", token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestComputeSessionToken_Deterministic(t *testing.T) {
	secret1 := []byte("secret-one")
	secret2 := []byte("secret-two")

	t1a := computeSessionToken(secret1)
	t1b := computeSessionToken(secret1)
	t2 := computeSessionToken(secret2)

	if t1a != t1b {
		t.Errorf("same secret produced different tokens: %q vs %q", t1a, t1b)
	}
	if t1a == t2 {
		t.Errorf("different secrets produced same token: %q", t1a)
	}
	// Token should be hex-encoded 16 bytes = 32 hex chars.
	if len(t1a) != 32 {
		t.Errorf("token length = %d, want 32", len(t1a))
	}
}
