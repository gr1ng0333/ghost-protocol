// Package ghost provides the gomobile-compatible API for the Ghost VPN client
// on Android. It is compiled into an AAR via gomobile bind.
package ghost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ghost/internal/auth"
	"ghost/internal/framing"
	"ghost/internal/mux"
	"ghost/internal/proxy"
	"ghost/internal/shaping"
	"ghost/internal/transport"
)

// ────────────────────── Socket Protection ────────────────────────

// SocketProtector is implemented by the Android VpnService to protect
// transport sockets from being routed through the VPN tunnel.
// The Protect method must be called on a socket fd BEFORE connect().
type SocketProtector interface {
	// Protect marks the socket to bypass the VPN tunnel.
	// Returns true on success, false on failure.
	Protect(fd int32) bool
}

var socketProtector SocketProtector

// SetSocketProtector registers the Android VpnService socket protector.
// Must be called before Start().
func SetSocketProtector(p SocketProtector) {
	socketProtector = p
}

// protectedDialer returns a net.Dialer whose Control function calls
// the registered SocketProtector on each new socket before it connects.
// It is injected into transport.H2Config.NetDialer so every outbound TCP
// connection made by the Ghost transport is protected from the VPN tunnel.
func protectedDialer() *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if socketProtector == nil {
				return nil // No protector registered, skip
			}
			var protectErr error
			controlErr := c.Control(func(fd uintptr) {
				if !socketProtector.Protect(int32(fd)) {
					protectErr = fmt.Errorf("VpnService.protect(%d) failed", fd)
				}
			})
			if controlErr != nil {
				return fmt.Errorf("rawconn control: %w", controlErr)
			}
			return protectErr
		},
	}
}

// ──────────────────────────── Logging ────────────────────────────

// LogCallback is the interface for log message delivery to the host app.
// gomobile will generate a Java/Kotlin interface for this.
type LogCallback interface {
	Log(level, message string)
}

var (
	logCBMu sync.Mutex
	logCB   LogCallback
)

// SetLogCallback sets a callback for log messages.
// Must be called BEFORE Start(). If not called, logs go to stderr.
func SetLogCallback(cb LogCallback) {
	logCBMu.Lock()
	logCB = cb
	logCBMu.Unlock()
}

// callbackHandler adapts LogCallback to slog.Handler.
type callbackHandler struct {
	cb    LogCallback
	level slog.Level
}

func (h *callbackHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *callbackHandler) Handle(_ context.Context, r slog.Record) error {
	h.cb.Log(r.Level.String(), r.Message)
	return nil
}
func (h *callbackHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *callbackHandler) WithGroup(_ string) slog.Handler      { return h }

// ──────────────────────────── Config ─────────────────────────────

// mobileConfig mirrors the JSON config passed from the Android app.
type mobileConfig struct {
	ServerAddr       string `json:"server_addr"`
	ServerSNI        string `json:"server_sni"`
	ServerPublicKey  string `json:"server_public_key"`
	ClientPrivateKey string `json:"client_private_key"`
	ShapingMode      string `json:"shaping_mode"`
	AutoMode         bool   `json:"auto_mode"`
	LogLevel         string `json:"log_level"`
}

func parseMobileConfig(jsonStr string) (*mobileConfig, error) {
	var cfg mobileConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("missing required field: server_addr")
	}
	if cfg.ServerSNI == "" {
		return nil, fmt.Errorf("missing required field: server_sni")
	}
	if cfg.ServerPublicKey == "" {
		return nil, fmt.Errorf("missing required field: server_public_key")
	}
	if cfg.ClientPrivateKey == "" {
		return nil, fmt.Errorf("missing required field: client_private_key")
	}
	return &cfg, nil
}

func decodeKey(s string) ([32]byte, error) {
	var key [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("hex decode: %w", err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

func parseMode(s string) shaping.Mode {
	switch s {
	case "stealth":
		return shaping.ModeStealth
	case "balanced":
		return shaping.ModeBalanced
	case "performance":
		return shaping.ModePerformance
	default:
		return shaping.ModeBalanced
	}
}

func parseSlogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ──────────────────────── Embedded profile ────────────────────────

// defaultProfileJSON is the chrome_browsing profile embedded as a constant
// so that Android builds don't need filesystem access to profiles/.
const defaultProfileJSON = `{
  "name": "chrome_browsing",
  "size_distribution": {
    "type": "empirical",
    "params": [],
    "samples": [
      19, 19, 45, 48, 52, 52, 52, 56, 65, 65,
      65, 82, 95, 111, 113, 116, 127, 135, 138, 159,
      167, 171, 173, 175, 175, 177, 178, 178, 179, 179,
      180, 180, 180, 181, 181, 181, 181, 182, 182, 182,
      183, 183, 184, 184, 184, 185, 185, 186, 186, 186,
      187, 187, 188, 188, 189, 189, 189, 190, 191, 193,
      207, 255, 293, 319, 328, 347, 353, 367, 457, 463,
      518, 594, 634, 636, 638, 640, 795, 996, 1266, 1374,
      2020, 2725, 4046, 4139, 4772, 6360, 8209, 8209, 8209, 8209,
      8209, 8209, 8209, 8209, 8209, 8209, 8209, 8209, 8209, 8230,
      8230
    ]
  },
  "timing_distribution": {
    "type": "lognormal",
    "params": [2.02, 2.78]
  },
  "burst_config": {
    "min_burst_bytes": 52,
    "max_burst_bytes": 11946,
    "min_pause_ms": 13,
    "max_pause_ms": 1006,
    "burst_count_distribution": {
      "type": "uniform",
      "params": [1, 9]
    }
  }
}`

func loadEmbeddedProfile() (*shaping.Profile, error) {
	var prof shaping.Profile
	if err := json.Unmarshal([]byte(defaultProfileJSON), &prof); err != nil {
		return nil, fmt.Errorf("embedded profile: %w", err)
	}
	return &prof, nil
}

// ──────────────────────────── Client ─────────────────────────────

// Client is the main Ghost VPN client handle.
type Client struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	mgr     *proxy.ConnManager
	tunFile *os.File
	stopTun func() // tears down gVisor stack

	// stats bookkeeping
	started  time.Time
	selector *shaping.AdaptiveSelector
	mode     atomic.Value // stores string

	// shaping components (kept for mode switching)
	profile  *shaping.Profile
	autoMode bool
}

// Start initializes Ghost VPN with the given TUN file descriptor and config.
// fd is the TUN file descriptor from Android VpnService.establish().detachFd().
// configJSON is a JSON string with fields: server_addr, server_sni,
// server_public_key, client_private_key, shaping_mode, auto_mode, log_level.
// Returns a Client handle, or error.
func Start(fd int, configJSON string) (*Client, error) {
	// 1. Parse config
	cfg, err := parseMobileConfig(configJSON)
	if err != nil {
		return nil, fmt.Errorf("ghost.Start: %w", err)
	}

	// 2. Set up logging
	level := parseSlogLevel(cfg.LogLevel)
	logCBMu.Lock()
	cb := logCB
	logCBMu.Unlock()
	if cb != nil {
		slog.SetDefault(slog.New(&callbackHandler{cb: cb, level: level}))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	}

	// 3. Decode keys
	serverPub, err := decodeKey(cfg.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ghost.Start: server_public_key: %w", err)
	}
	clientPriv, err := decodeKey(cfg.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ghost.Start: client_private_key: %w", err)
	}

	// 4. Create ClientAuth
	clientAuth, err := auth.NewClientAuth(clientPriv, serverPub)
	if err != nil {
		return nil, fmt.Errorf("ghost.Start: auth: %w", err)
	}

	// 5. Compute shared secret for path derivation
	sharedSecret, err := auth.SharedSecret(clientPriv, serverPub)
	if err != nil {
		return nil, fmt.Errorf("ghost.Start: shared secret: %w", err)
	}

	// 6. Create Dialer — inject protectedDialer so every outbound TCP socket
	// is protected via VpnService.protect() before connect().
	h2cfg := transport.DefaultChromeH2Config()
	h2cfg.NetDialer = protectedDialer()
	dialer := transport.NewDialer(h2cfg, clientAuth)

	// 7. Load shaping profile
	profile, err := loadEmbeddedProfile()
	if err != nil {
		slog.Warn("shaping profile load failed, disabling shaping", "error", err)
	}

	// 8. Build shaping components
	mode := parseMode(cfg.ShapingMode)
	selector := shaping.NewAdaptiveSelector(mode, cfg.AutoMode)
	seed := time.Now().UnixNano()

	var (
		wrap          *mux.PipelineWrap
		timerWriter   *shaping.TimerFrameWriter
		wrappedWriter framing.FrameWriter
	)

	if profile != nil {
		padder := shaping.NewProfilePadder(profile, seed)
		timer := shaping.NewProfileTimer(profile, seed+1)

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
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 9. Create ConnManager
	mgr := proxy.NewConnManager(proxy.ConnManagerConfig{
		Dialer:     dialer,
		ServerAddr: cfg.ServerAddr,
		ServerSNI:  cfg.ServerSNI,
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
		cancel()
		return nil, fmt.Errorf("ghost.Start: connect: %w", err)
	}

	opener := mgr.StreamOpener()

	// 10. Set up gVisor netstack from fd
	tunFile := os.NewFile(uintptr(fd), "tun")
	stopTun, err := setupNetstack(ctx, tunFile, 1500, opener)
	if err != nil {
		mgr.Stop()
		cancel()
		tunFile.Close()
		return nil, fmt.Errorf("ghost.Start: netstack: %w", err)
	}

	c := &Client{
		ctx:      ctx,
		cancel:   cancel,
		mgr:      mgr,
		tunFile:  tunFile,
		stopTun:  stopTun,
		started:  time.Now(),
		selector: selector,
		profile:  profile,
		autoMode: cfg.AutoMode,
	}
	c.mode.Store(cfg.ShapingMode)
	if c.mode.Load().(string) == "" {
		c.mode.Store("balanced")
	}

	slog.Info("ghost client started", "server", cfg.ServerAddr)
	return c, nil
}

// Stop disconnects and cleans up all resources.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel == nil {
		return // already stopped
	}

	c.cancel()

	if c.stopTun != nil {
		c.stopTun()
	}
	if c.mgr != nil {
		c.mgr.Stop()
	}
	if c.tunFile != nil {
		c.tunFile.Close()
	}

	c.cancel = nil
	slog.Info("ghost client stopped")
}

// Healthy returns true if the tunnel is connected and active.
func (c *Client) Healthy() bool {
	c.mu.Lock()
	mgr := c.mgr
	c.mu.Unlock()
	if mgr == nil {
		return false
	}
	return mgr.Healthy()
}

// Stats returns JSON-encoded statistics string.
func (c *Client) Stats() string {
	c.mu.Lock()
	mgr := c.mgr
	started := c.started
	c.mu.Unlock()

	healthy := false
	if mgr != nil {
		healthy = mgr.Healthy()
	}

	m := c.mode.Load()
	modeStr := "balanced"
	if m != nil {
		modeStr = m.(string)
	}

	s := struct {
		Connected     bool   `json:"connected"`
		Mode          string `json:"mode"`
		BytesSent     uint64 `json:"bytes_sent"`
		BytesRecv     uint64 `json:"bytes_recv"`
		ActiveStreams int    `json:"active_streams"`
		UptimeSec     int64  `json:"uptime_sec"`
	}{
		Connected: healthy,
		Mode:      modeStr,
		UptimeSec: int64(time.Since(started).Seconds()),
	}

	data, _ := json.Marshal(s)
	return string(data)
}

// SetMode changes the shaping mode: "stealth", "balanced", "performance".
func (c *Client) SetMode(mode string) {
	switch mode {
	case "stealth", "balanced", "performance":
		c.mode.Store(mode)
		// AdaptiveSelector's defaultMode is unexported, so we recreate it.
		// However the selector is shared by reference in the pipeline, so
		// we swap the pointer atomically via the Client's selector field.
		// Since AdaptiveSelector.Select is called on each frame write, the
		// new mode takes effect on the next frame.
		newSelector := shaping.NewAdaptiveSelector(parseMode(mode), c.autoMode)
		c.mu.Lock()
		c.selector = newSelector
		c.mu.Unlock()
		slog.Info("shaping mode changed", "mode", mode)
	default:
		slog.Warn("unknown shaping mode, ignoring", "mode", mode)
	}
}

// ──────────────────────── Helpers ─────────────────────────────

// muxStatsAdapter wraps a ClientMux to satisfy shaping.MuxStatsProvider.
type muxStatsAdapter struct {
	getMuxStats func() mux.MuxStats
}

func (a *muxStatsAdapter) ActiveStreamCount() int { return a.getMuxStats().ActiveStreams }
func (a *muxStatsAdapter) TotalBytesSent() uint64 { return a.getMuxStats().BytesSent }
func (a *muxStatsAdapter) TotalBytesRecv() uint64 { return a.getMuxStats().BytesRecv }
