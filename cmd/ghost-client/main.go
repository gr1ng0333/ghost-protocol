package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"
	"ghost/internal/framing"
	"ghost/internal/mux"
	"ghost/internal/proxy"
	"ghost/internal/shaping"
	"ghost/internal/transport"
)

func main() {
	cfgPath := flag.String("config", "configs/client.yaml", "path to client config file")
	flag.Parse()

	// Load configuration.
	var cfg config.ClientConfig
	if err := config.Load(*cfgPath, &cfg); err != nil {
		slog.Error("failed to load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	cfg.Defaults()

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(1)
	}

	// Setup logging.
	initLogging(cfg.Log)

	// Parse auth keys from hex.
	serverPub, err := decodeKey(cfg.Auth.ServerPublicKey, "server_public_key")
	if err != nil {
		slog.Error("invalid auth key", "err", err)
		os.Exit(1)
	}
	clientPriv, err := decodeKey(cfg.Auth.ClientPrivateKey, "client_private_key")
	if err != nil {
		slog.Error("invalid auth key", "err", err)
		os.Exit(1)
	}

	// Create client auth.
	clientAuth, err := auth.NewClientAuth(clientPriv, serverPub)
	if err != nil {
		slog.Error("failed to create client auth", "err", err)
		os.Exit(1)
	}

	// Compute shared secret for path derivation.
	sharedSecret, err := auth.SharedSecret(clientPriv, serverPub)
	if err != nil {
		slog.Error("failed to compute shared secret", "err", err)
		os.Exit(1)
	}

	// Create transport dialer and connect.
	dialer := transport.NewDialer(transport.DefaultChromeH2Config(), clientAuth)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load traffic profile for shaping (optional).
	var (
		wrap          *mux.PipelineWrap
		profile       *shaping.Profile
		selector      *shaping.AdaptiveSelector
		timerWriter   *shaping.TimerFrameWriter
		wrappedWriter framing.FrameWriter
		shapingSeed   int64
	)
	if p, err := shaping.LoadProfile(cfg.Shaping.ProfilePath); err == nil {
		profile = p
		shapingSeed = time.Now().UnixNano()
		padder := shaping.NewProfilePadder(profile, shapingSeed)
		timer := shaping.NewProfileTimer(profile, shapingSeed+1)
		selector = shaping.NewAdaptiveSelector(parseShapingMode(cfg.Shaping.DefaultMode), cfg.Shaping.AutoMode)

		wrap = &mux.PipelineWrap{
			WrapWriter: func(w framing.FrameWriter) framing.FrameWriter {
				padded := &shaping.PadderFrameWriter{Padder: padder, Next: w}
				timerWriter = &shaping.TimerFrameWriter{
					Timer: timer, Selector: selector, Next: padded,
				}
				wrappedWriter = timerWriter
				return timerWriter
			},
			WrapReader: func(r framing.FrameReader) framing.FrameReader {
				return &shaping.UnpadderFrameReader{Padder: padder, Src: r}
			},
		}
		slog.Info("traffic shaping enabled", "profile", profile.Name)
	} else {
		slog.Info("traffic shaping disabled (no profile found)", "err", err)
	}

	// Create ConnManager with per-pipeline PostConnect wiring.
	mgr := proxy.NewConnManager(proxy.ConnManagerConfig{
		Dialer:     dialer,
		ServerAddr: cfg.Server.Addr,
		ServerSNI:  cfg.Server.SNI,
		Pipeline: proxy.PipelineOpts{
			Wrap:         wrap,
			SharedSecret: sharedSecret,
			PostConnect: func(p *mux.ClientPipeline) (cleanup func()) {
				if wrappedWriter == nil || profile == nil {
					return nil
				}
				pCtx, pCancel := context.WithCancel(ctx)

				cover := shaping.NewCoverGenerator(wrappedWriter, selector, profile, time.Now().UnixNano())
				cover.Start(pCtx)

				statsAdapter := &muxStatsAdapter{getMuxStats: p.Mux.Stats}
				updater := shaping.NewStatsUpdater(statsAdapter, timerWriter, cover, 1*time.Second)
				go updater.Run(pCtx)

				slog.Info("cover traffic generator started")

				return func() {
					pCancel()
					cover.Stop()
				}
			},
		},
		HealthCheck:   5 * time.Second,
		FreezeTimeout: 10 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		slog.Error("initial connection failed", "err", err)
		os.Exit(1)
	}
	defer mgr.Stop()

	opener := mgr.StreamOpener()

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	mode := cfg.Proxy.Mode
	if mode == "" {
		mode = "socks5"
	}

	switch mode {
	case "socks5":
		socks5 := proxy.NewSOCKS5Server()
		socks5Addr := cfg.Proxy.Socks5
		if socks5Addr == "" {
			socks5Addr = "127.0.0.1:1080"
		}
		go func() {
			if err := socks5.ListenAndServe(ctx, socks5Addr, opener); err != nil {
				slog.Error("socks5 server failed", "err", err)
			}
		}()

		slog.Info("ghost client started (socks5 mode)",
			"server", cfg.Server.Addr, "proxy", socks5Addr)

		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)

		cancel()
		socks5.Close()

	case "tun":
		serverHost, _, err := net.SplitHostPort(cfg.Server.Addr)
		if err != nil {
			slog.Error("invalid server address", "addr", cfg.Server.Addr, "error", err)
			os.Exit(1)
		}

		tunName := cfg.Proxy.TunName
		if tunName == "" {
			tunName = "ghost0"
		}

		tunDev := newTunDevice(tunName, "10.0.85.1", serverHost)
		if tunDev == nil {
			slog.Error("tun mode not supported on this platform")
			os.Exit(1)
		}
		if err := tunDev.Start(ctx, opener); err != nil {
			slog.Error("tun device failed to start", "error", err)
			os.Exit(1)
		}

		slog.Info("ghost client started (tun mode)",
			"server", cfg.Server.Addr, "tun", tunName)

		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)

		cancel()
		tunDev.Stop()

	default:
		slog.Error("unknown proxy mode", "mode", mode)
		os.Exit(1)
	}

	slog.Info("ghost client stopped")
}

// decodeKey decodes a 32-byte hex-encoded key.
func decodeKey(s, name string) ([32]byte, error) {
	var key [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return key, &keyError{name: name, err: err}
	}
	if len(raw) != 32 {
		return key, &keyError{name: name, err: errKeyLen}
	}
	copy(key[:], raw)
	return key, nil
}

type keyError struct {
	name string
	err  error
}

func (e *keyError) Error() string { return e.name + ": " + e.err.Error() }
func (e *keyError) Unwrap() error { return e.err }

var errKeyLen = &strError{"expected 32 bytes"}

type strError struct{ s string }

// muxStatsAdapter wraps a ClientMux to satisfy shaping.MuxStatsProvider.
type muxStatsAdapter struct {
	getMuxStats func() mux.MuxStats
}

func (a *muxStatsAdapter) ActiveStreamCount() int { return a.getMuxStats().ActiveStreams }
func (a *muxStatsAdapter) TotalBytesSent() uint64 { return a.getMuxStats().BytesSent }
func (a *muxStatsAdapter) TotalBytesRecv() uint64 { return a.getMuxStats().BytesRecv }

func (e *strError) Error() string { return e.s }

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

// parseShapingMode maps a config string to a shaping.Mode constant.
func parseShapingMode(s string) shaping.Mode {
	switch strings.ToLower(s) {
	case "stealth":
		return shaping.ModeStealth
	case "performance":
		return shaping.ModePerformance
	default:
		return shaping.ModeBalanced
	}
}
