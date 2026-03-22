package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ghost/internal/config"
	"ghost/internal/transport"
)

func main() {
	// Determine config path.
	cfgPath := "configs/server.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	// Load server configuration.
	var cfg config.ServerConfig
	if err := config.Load(cfgPath, &cfg); err != nil {
		slog.Error("failed to load config", "path", cfgPath, "err", err)
		os.Exit(1)
	}

	// Generate self-signed certificate using config domain.
	domain := cfg.Domain
	if domain == "" {
		domain = "localhost"
	}
	tlsCert, err := transport.GenerateSelfSignedCert(domain)
	if err != nil {
		slog.Error("failed to generate TLS certificate", "err", err)
		os.Exit(1)
	}
	slog.Info("generated self-signed certificate", "domain", domain)

	// Derive shared secret from server private key, or use a default.
	secret := deriveSecret(cfg.Auth.ServerPrivateKey)

	// Create server.
	srv := transport.NewServer(&cfg, tlsCert, secret)

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
		srv.Close()
	}()

	// Start listening.
	addr := cfg.Listen
	if addr == "" {
		addr = ":443"
	}
	fallback := cfg.Fallback.Addr

	slog.Info("starting ghost server", "addr", addr, "fallback", fallback)
	if err := srv.ListenAndServe(ctx, addr, fallback); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// deriveSecret produces a shared secret from the server private key hex string.
// If the key is empty, returns a deterministic default for development.
func deriveSecret(privateKeyHex string) []byte {
	if privateKeyHex == "" || privateKeyHex == "0000000000000000000000000000000000000000000000000000000000000000" {
		h := sha256.Sum256([]byte("ghost-dev-secret"))
		return h[:]
	}
	raw, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		h := sha256.Sum256([]byte(privateKeyHex))
		return h[:]
	}
	h := sha256.Sum256(raw)
	return h[:]
}
