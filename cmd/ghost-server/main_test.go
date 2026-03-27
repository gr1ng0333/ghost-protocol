package main

import (
	"strings"
	"testing"

	"ghost/internal/config"
)

func TestBuildServerAuth_EmptyClientPublicKey(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "70f9bf7792fdf80fec2d11e5bdfe4199a461cc9376f2f2d160d843386c122a2a",
		ClientPublicKey:  "",
	}
	_, err := buildServerAuth(ac)
	if err == nil {
		t.Fatal("expected error for empty client_public_key, got nil")
	}
	if !strings.Contains(err.Error(), "client_public_key is required") {
		t.Errorf("error = %q, want it to mention client_public_key is required", err)
	}
}

func TestBuildServerAuth_InvalidServerPrivateKeyHex(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "not-valid-hex",
		ClientPublicKey:  "70f9bf7792fdf80fec2d11e5bdfe4199a461cc9376f2f2d160d843386c122a2a",
	}
	_, err := buildServerAuth(ac)
	if err == nil {
		t.Fatal("expected error for invalid server_private_key hex, got nil")
	}
	if !strings.Contains(err.Error(), "server_private_key") {
		t.Errorf("error = %q, want it to mention server_private_key", err)
	}
}

func TestBuildServerAuth_InvalidClientPublicKeyHex(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "70f9bf7792fdf80fec2d11e5bdfe4199a461cc9376f2f2d160d843386c122a2a",
		ClientPublicKey:  "short",
	}
	_, err := buildServerAuth(ac)
	if err == nil {
		t.Fatal("expected error for invalid client_public_key hex, got nil")
	}
	if !strings.Contains(err.Error(), "client_public_key") {
		t.Errorf("error = %q, want it to mention client_public_key", err)
	}
}

func TestBuildServerAuth_ValidKeys(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "70f9bf7792fdf80fec2d11e5bdfe4199a461cc9376f2f2d160d843386c122a2a",
		ClientPublicKey:  "4207bd1ed1cefb63199c431b48536767b6744a89613a85f5214b09d4d6dec360",
	}
	sa, err := buildServerAuth(ac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sa == nil {
		t.Fatal("expected non-nil ServerAuth")
	}
}

func TestBuildServerAuth_DevKeyGeneration(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "", // should trigger dev key generation
		ClientPublicKey:  "4207bd1ed1cefb63199c431b48536767b6744a89613a85f5214b09d4d6dec360",
	}
	sa, err := buildServerAuth(ac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sa == nil {
		t.Fatal("expected non-nil ServerAuth with generated dev key")
	}
}
