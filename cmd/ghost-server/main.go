package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(1)
	}

	initLogging(cfg.Log)

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

	// Create metrics collector.
	metrics := transport.NewMetrics()
	sm.OnRegister = metrics.SessionOpened
	sm.OnRemove = metrics.SessionClosed

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

	// Health endpoint — localhost only.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		snap := metrics.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"healthy":        true,
			"sessions":       snap.ActiveSessions,
			"total_sessions": snap.TotalSessions,
			"uptime_seconds": time.Since(snap.Uptime).Seconds(),
			"bytes_sent":     snap.TotalBytesSent,
			"bytes_recv":     snap.TotalBytesRecv,
			"reconnects":     snap.ReconnectCount,
		})
	})
	go func() {
		if err := http.ListenAndServe("127.0.0.1:9090", healthMux); err != nil {
			slog.Error("health endpoint failed", "err", err)
		}
	}()
	slog.Info("health endpoint started", "addr", "127.0.0.1:9090")

	// Notify systemd that startup is complete (Type=notify).
	if err := sdNotify("READY=1"); err != nil {
		slog.Warn("sd_notify READY failed", "err", err)
	}

	// Systemd watchdog: ping every 60s (WatchdogSec=120 in service file).
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := sdNotify("WATCHDOG=1"); err != nil {
					slog.Warn("watchdog notify failed", "err", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Periodic metrics logging.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				snap := metrics.Snapshot()
				slog.Info("metrics",
					"sessions", snap.ActiveSessions,
					"total_sessions", snap.TotalSessions,
					"bytes_sent", snap.TotalBytesSent,
					"bytes_recv", snap.TotalBytesRecv,
					"uptime", time.Since(snap.Uptime).String(),
					"reconnects", snap.ReconnectCount,
				)
			case <-ctx.Done():
				return
			}
		}
	}()

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
			return nil, fmt.Errorf("invalid server_private_key hex (must be 64 hex chars / 32 bytes)")
		}
		copy(serverPriv[:], raw)
	}

	if ac.ClientPublicKey == "" {
		return nil, fmt.Errorf("auth.client_public_key is required but empty")
	}
	raw, err := hex.DecodeString(ac.ClientPublicKey)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("invalid client_public_key hex (must be 64 hex chars / 32 bytes)")
	}
	var clientPub [32]byte
	copy(clientPub[:], raw)

	return auth.NewServerAuth(serverPriv, [][32]byte{clientPub})
}

// initLogging configures the default slog logger from LogConfig.
func initLogging(cfg config.LogConfig) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}

	out := os.Stdout
	if cfg.File != "" && cfg.File != "stdout" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			slog.Error("failed to open log file, using stdout", "file", cfg.File, "err", err)
		} else {
			out = f
		}
	}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(out, opts)
	} else {
		handler = slog.NewJSONHandler(out, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// sdNotify sends a notification to systemd via the sd_notify protocol.
// Does nothing if NOTIFY_SOCKET is not set (i.e., not running under systemd).
func sdNotify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		return fmt.Errorf("sdNotify dial: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
