package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/shaping"
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
	cfg.Defaults()

	// Create certificate manager.
	domain := cfg.Domain
	if domain == "" {
		domain = "localhost"
	}
	certMgr, err := transport.NewCertManager(
		domain,
		cfg.TLS.AutoCert,
		cfg.TLS.Email,
		cfg.TLS.CacheDir,
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
		slog.Default(),
	)
	if err != nil {
		slog.Error("failed to create certificate manager", "err", err)
		os.Exit(1)
	}
	tlsConfig := certMgr.TLSConfig()

	// Build ServerAuth from config keys.
	sa, err := buildServerAuth(cfg.Auth)
	if err != nil {
		slog.Error("failed to build server auth", "err", err)
		os.Exit(1)
	}

	// Load traffic shaping profile (optional).
	profile, profileErr := shaping.LoadProfile(cfg.Shaping.ProfilePath)
	if profileErr != nil {
		slog.Info("traffic shaping disabled (no profile found)", "err", profileErr)
	} else {
		slog.Info("traffic shaping enabled", "profile", profile.Name)
	}

	// Parse shaping mode.
	var shapingMode shaping.Mode
	switch cfg.Shaping.DefaultMode {
	case "stealth":
		shapingMode = shaping.ModeStealth
	case "performance":
		shapingMode = shaping.ModePerformance
	default:
		shapingMode = shaping.ModeBalanced
	}

	// Create session manager.
	idleTimeout := time.Duration(cfg.Sessions.IdleTimeoutSec) * time.Second
	sm := transport.NewSessionManager(cfg.Sessions.MaxSessions, idleTimeout, slog.Default())

	// Create server with session management and per-session shaping.
	srv := transport.NewServerWithSessions(&cfg, tlsConfig, sa, sm, profile, shapingMode, cfg.Shaping.AutoMode)

	// Attach CertManager for ACME support.
	if gs, ok := srv.(interface{ SetCertManager(*transport.CertManager) }); ok {
		gs.SetCertManager(certMgr)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start session cleanup loop.
	go sm.RunCleanupLoop(ctx, 60*time.Second)

	// Start cert file watcher (manual mode only).
	certMgr.StartFileWatcher(ctx)

	// Start HTTP-01 challenge handler on :80 (autocert mode only).
	if h := certMgr.HTTPHandler(); h != nil {
		go func() {
			httpSrv := &http.Server{
				Addr:    ":80",
				Handler: h,
			}
			go func() {
				<-ctx.Done()
				httpSrv.Close()
			}()
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP-01 listener failed", "err", err)
			}
		}()
	}

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
