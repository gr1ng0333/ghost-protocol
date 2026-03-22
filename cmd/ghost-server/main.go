package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ghost/internal/auth"
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

	// Build ServerAuth from config keys.
	sa, err := buildServerAuth(cfg.Auth)
	if err != nil {
		slog.Error("failed to build server auth", "err", err)
		os.Exit(1)
	}

	// Create server.
	srv := transport.NewServer(&cfg, tlsCert, sa)

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

// buildServerAuth creates a ServerAuth from the config's key material.
// If the private key or client key is empty, generates dev keys for development.
func buildServerAuth(ac config.AuthConfig) (auth.ServerAuth, error) {
	var serverPriv [32]byte
	if ac.ServerPrivateKey == "" || ac.ServerPrivateKey == "0000000000000000000000000000000000000000000000000000000000000000" {
		kp, err := auth.GenKeyPair()
		if err != nil {
			return nil, err
		}
		serverPriv = kp.Private
		slog.Warn("using generated dev server key (not for production)")
	} else {
		raw, err := hex.DecodeString(ac.ServerPrivateKey)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid server_private_key hex")
		}
		copy(serverPriv[:], raw)
	}

	var clientPubs [][32]byte
	if ac.ClientPublicKey != "" {
		raw, err := hex.DecodeString(ac.ClientPublicKey)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid client_public_key hex")
		}
		var pub [32]byte
		copy(pub[:], raw)
		clientPubs = append(clientPubs, pub)
	}

	return auth.NewServerAuth(serverPriv, clientPubs)
}
