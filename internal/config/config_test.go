package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ClientConfig(t *testing.T) {
	yaml := `
server:
  addr: "203.0.113.42:443"
  sni: "example.com"
auth:
  server_public_key: "abc123"
proxy:
  mode: "socks5"
  socks5: "127.0.0.1:1080"
  dns: "1.1.1.1:53"
shaping:
  default_mode: "balanced"
  profile_dir: "profiles/"
  auto_mode: true
log:
  level: "info"
  file: "stdout"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	var cfg ClientConfig
	if err := Load(path, &cfg); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Addr != "203.0.113.42:443" {
		t.Errorf("Server.Addr = %q, want %q", cfg.Server.Addr, "203.0.113.42:443")
	}
	if cfg.Server.SNI != "example.com" {
		t.Errorf("Server.SNI = %q, want %q", cfg.Server.SNI, "example.com")
	}
	if cfg.Auth.ServerPublicKey != "abc123" {
		t.Errorf("Auth.ServerPublicKey = %q, want %q", cfg.Auth.ServerPublicKey, "abc123")
	}
	if cfg.Proxy.Mode != "socks5" {
		t.Errorf("Proxy.Mode = %q, want %q", cfg.Proxy.Mode, "socks5")
	}
	if cfg.Proxy.Socks5 != "127.0.0.1:1080" {
		t.Errorf("Proxy.Socks5 = %q, want %q", cfg.Proxy.Socks5, "127.0.0.1:1080")
	}
	if cfg.Proxy.DNS != "1.1.1.1:53" {
		t.Errorf("Proxy.DNS = %q, want %q", cfg.Proxy.DNS, "1.1.1.1:53")
	}
	if cfg.Shaping.DefaultMode != "balanced" {
		t.Errorf("Shaping.DefaultMode = %q, want %q", cfg.Shaping.DefaultMode, "balanced")
	}
	if cfg.Shaping.ProfileDir != "profiles/" {
		t.Errorf("Shaping.ProfileDir = %q, want %q", cfg.Shaping.ProfileDir, "profiles/")
	}
	if !cfg.Shaping.AutoMode {
		t.Error("Shaping.AutoMode = false, want true")
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Log.File != "stdout" {
		t.Errorf("Log.File = %q, want %q", cfg.Log.File, "stdout")
	}
}

func TestLoad_ServerConfig(t *testing.T) {
	yaml := `
listen: ":443"
domain: "example.com"
auth:
  server_public_key: "pubkey"
  server_private_key: "privkey"
backend:
  allowed_ports: [80, 443]
shaping:
  default_mode: "balanced"
  profile_dir: "profiles/"
  auto_mode: true
fallback:
  addr: "127.0.0.1:8080"
  web_root: "/var/www/html"
  use_caddy: true
sessions:
  max_sessions: 10
  idle_timeout_sec: 300
log:
  level: "info"
  file: "stdout"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	var cfg ServerConfig
	if err := Load(path, &cfg); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Listen != ":443" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":443")
	}
	if cfg.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", cfg.Domain, "example.com")
	}
	if cfg.Auth.ServerPublicKey != "pubkey" {
		t.Errorf("Auth.ServerPublicKey = %q, want %q", cfg.Auth.ServerPublicKey, "pubkey")
	}
	if cfg.Auth.ServerPrivateKey != "privkey" {
		t.Errorf("Auth.ServerPrivateKey = %q, want %q", cfg.Auth.ServerPrivateKey, "privkey")
	}
	if len(cfg.Backend.AllowedPorts) != 2 || cfg.Backend.AllowedPorts[0] != 80 || cfg.Backend.AllowedPorts[1] != 443 {
		t.Errorf("Backend.AllowedPorts = %v, want [80 443]", cfg.Backend.AllowedPorts)
	}
	if cfg.Shaping.DefaultMode != "balanced" {
		t.Errorf("Shaping.DefaultMode = %q, want %q", cfg.Shaping.DefaultMode, "balanced")
	}
	if !cfg.Shaping.AutoMode {
		t.Error("Shaping.AutoMode = false, want true")
	}
	if cfg.Fallback.Addr != "127.0.0.1:8080" {
		t.Errorf("Fallback.Addr = %q, want %q", cfg.Fallback.Addr, "127.0.0.1:8080")
	}
	if cfg.Fallback.WebRoot != "/var/www/html" {
		t.Errorf("Fallback.WebRoot = %q, want %q", cfg.Fallback.WebRoot, "/var/www/html")
	}
	if !cfg.Fallback.UseCaddy {
		t.Error("Fallback.UseCaddy = false, want true")
	}
	if cfg.Sessions.MaxSessions != 10 {
		t.Errorf("Sessions.MaxSessions = %d, want 10", cfg.Sessions.MaxSessions)
	}
	if cfg.Sessions.IdleTimeoutSec != 300 {
		t.Errorf("Sessions.IdleTimeoutSec = %d, want 300", cfg.Sessions.IdleTimeoutSec)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	var cfg ClientConfig
	err := Load("/nonexistent/path/config.yaml", &cfg)
	if err == nil {
		t.Fatal("Load should return error for nonexistent file")
	}
	t.Logf("got expected error: %v", err)
}
