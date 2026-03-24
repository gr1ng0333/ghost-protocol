package main

import (
	"strings"
	"testing"

	"ghost/internal/config"
)

func TestBuildServerAuth_EmptyClientPublicKey(t *testing.T) {
	ac := config.AuthConfig{
		ServerPrivateKey: "e858568789b3522748dfba5542d367ac7e7d672b6d221bdef72c6cfd4480e623",
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
		ClientPublicKey:  "e858568789b3522748dfba5542d367ac7e7d672b6d221bdef72c6cfd4480e623",
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
		ServerPrivateKey: "e858568789b3522748dfba5542d367ac7e7d672b6d221bdef72c6cfd4480e623",
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
		ServerPrivateKey: "e858568789b3522748dfba5542d367ac7e7d672b6d221bdef72c6cfd4480e623",
		ClientPublicKey:  "e09fed315c42f932f94cc3c53ab7fb839b1b5dc6eef59bd26998c9407894cb63",
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
		ClientPublicKey:  "e09fed315c42f932f94cc3c53ab7fb839b1b5dc6eef59bd26998c9407894cb63",
	}
	sa, err := buildServerAuth(ac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sa == nil {
		t.Fatal("expected non-nil ServerAuth with generated dev key")
	}
}
