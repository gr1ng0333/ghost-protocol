package ghost

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ghost/internal/mux"
	"ghost/internal/shaping"
)

// validConfigJSON returns a valid JSON config string for testing.
func validConfigJSON() string {
	return `{
		"server_addr": "203.0.113.42:443",
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "` + strings.Repeat("cd", 32) + `",
		"shaping_mode": "balanced",
		"auto_mode": true,
		"log_level": "info"
	}`
}

func TestParseMobileConfig_Valid(t *testing.T) {
	cfg, err := parseMobileConfig(validConfigJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerAddr != "203.0.113.42:443" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "203.0.113.42:443")
	}
	if cfg.ServerSNI != "example.com" {
		t.Errorf("ServerSNI = %q, want %q", cfg.ServerSNI, "example.com")
	}
	if cfg.ShapingMode != "balanced" {
		t.Errorf("ShapingMode = %q, want %q", cfg.ShapingMode, "balanced")
	}
	if !cfg.AutoMode {
		t.Error("AutoMode = false, want true")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestParseMobileConfig_InvalidJSON(t *testing.T) {
	_, err := parseMobileConfig("{bad json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error = %q, want it to contain 'invalid JSON'", err)
	}
}

func TestParseMobileConfig_MissingServerAddr(t *testing.T) {
	cfg := `{
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	_, err := parseMobileConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing server_addr")
	}
	if !strings.Contains(err.Error(), "server_addr") {
		t.Errorf("error = %q, want it to mention server_addr", err)
	}
}

func TestParseMobileConfig_MissingKeys(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		field string
	}{
		{
			name: "missing server_public_key",
			json: `{
				"server_addr": "1.2.3.4:443",
				"server_sni": "example.com",
				"client_private_key": "` + strings.Repeat("cd", 32) + `"
			}`,
			field: "server_public_key",
		},
		{
			name: "missing client_private_key",
			json: `{
				"server_addr": "1.2.3.4:443",
				"server_sni": "example.com",
				"server_public_key": "` + strings.Repeat("ab", 32) + `"
			}`,
			field: "client_private_key",
		},
		{
			name: "missing server_sni",
			json: `{
				"server_addr": "1.2.3.4:443",
				"server_public_key": "` + strings.Repeat("ab", 32) + `",
				"client_private_key": "` + strings.Repeat("cd", 32) + `"
			}`,
			field: "server_sni",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMobileConfig(tc.json)
			if err == nil {
				t.Fatalf("expected error for missing %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error = %q, want it to mention %s", err, tc.field)
			}
		})
	}
}

func TestDecodeKey_Valid(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	key, err := decodeKey(hex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key[0] != 0xab || key[31] != 0xab {
		t.Error("key bytes mismatch")
	}
}

func TestDecodeKey_InvalidHex(t *testing.T) {
	_, err := decodeKey("not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestDecodeKey_WrongLength(t *testing.T) {
	_, err := decodeKey("abcd") // 2 bytes, not 32
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error = %q, want it to mention 32 bytes", err)
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"stealth", "stealth"},
		{"balanced", "balanced"},
		{"performance", "performance"},
		{"unknown", "balanced"}, // default
		{"", "balanced"},        // default
	}
	for _, tc := range cases {
		got := parseMode(tc.input)
		expected := parseMode(tc.want)
		if got != expected {
			t.Errorf("parseMode(%q) = %v, want %v", tc.input, got, expected)
		}
	}
}

func TestLoadEmbeddedProfile(t *testing.T) {
	p, err := loadEmbeddedProfile()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "chrome_browsing" {
		t.Errorf("Name = %q, want %q", p.Name, "chrome_browsing")
	}
	if p.SizeDist.Type != "empirical" {
		t.Errorf("SizeDist.Type = %q, want %q", p.SizeDist.Type, "empirical")
	}
	if len(p.SizeDist.Samples) == 0 {
		t.Error("SizeDist.Samples is empty")
	}
}

func TestClient_Stats_NoConnection(t *testing.T) {
	c := &Client{}
	c.mode.Store("balanced")

	s := c.Stats()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		t.Fatalf("Stats() returned invalid JSON: %v\nraw: %s", err, s)
	}
	if result["connected"] != false {
		t.Errorf("connected = %v, want false", result["connected"])
	}
	if result["mode"] != "balanced" {
		t.Errorf("mode = %v, want 'balanced'", result["mode"])
	}
}

func TestClient_SetMode_ValidModes(t *testing.T) {
	c := &Client{
		autoMode: false,
	}
	c.mode.Store("balanced")

	for _, m := range []string{"stealth", "balanced", "performance"} {
		c.SetMode(m)
		got := c.mode.Load().(string)
		if got != m {
			t.Errorf("after SetMode(%q): mode = %q", m, got)
		}
	}
}

func TestClient_SetMode_Invalid(t *testing.T) {
	c := &Client{
		autoMode: false,
	}
	c.mode.Store("balanced")

	c.SetMode("invalid_mode")
	got := c.mode.Load().(string)
	if got != "balanced" {
		t.Errorf("after SetMode(invalid): mode = %q, want 'balanced'", got)
	}
}

func TestClient_Healthy_NilManager(t *testing.T) {
	c := &Client{}
	if c.Healthy() {
		t.Error("Healthy() = true with nil manager, want false")
	}
}

// ──────── parseSlogLevel ────────

func TestParseSlogLevel(t *testing.T) {
	cases := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},        // default
		{"unknown", slog.LevelInfo}, // default
	}
	for _, tc := range cases {
		got := parseSlogLevel(tc.input)
		if got != tc.want {
			t.Errorf("parseSlogLevel(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ──────── SetLogCallback ────────

func TestSetLogCallback(t *testing.T) {
	// Save original and restore after test.
	logCBMu.Lock()
	origCB := logCB
	logCBMu.Unlock()
	defer func() {
		logCBMu.Lock()
		logCB = origCB
		logCBMu.Unlock()
	}()

	var captured []string
	cb := &testLogCallback{fn: func(level, message string) {
		captured = append(captured, level+":"+message)
	}}
	SetLogCallback(cb)

	logCBMu.Lock()
	got := logCB
	logCBMu.Unlock()

	if got == nil {
		t.Fatal("logCB is nil after SetLogCallback")
	}
}

func TestSetLogCallback_Nil(t *testing.T) {
	logCBMu.Lock()
	origCB := logCB
	logCBMu.Unlock()
	defer func() {
		logCBMu.Lock()
		logCB = origCB
		logCBMu.Unlock()
	}()

	SetLogCallback(nil)

	logCBMu.Lock()
	got := logCB
	logCBMu.Unlock()

	if got != nil {
		t.Fatal("logCB should be nil after SetLogCallback(nil)")
	}
}

type testLogCallback struct {
	fn func(level, message string)
}

func (t *testLogCallback) Log(level, message string) {
	t.fn(level, message)
}

// ──────── callbackHandler ────────

func TestCallbackHandler_Enabled(t *testing.T) {
	h := &callbackHandler{level: slog.LevelWarn}

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled should return false for Debug when level is Warn")
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled should return false for Info when level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Enabled should return true for Warn when level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Enabled should return true for Error when level is Warn")
	}
}

func TestCallbackHandler_Handle(t *testing.T) {
	var gotLevel, gotMessage string
	cb := &testLogCallback{fn: func(level, message string) {
		gotLevel = level
		gotMessage = message
	}}
	h := &callbackHandler{cb: cb, level: slog.LevelInfo}

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	if err := h.Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if gotLevel != "INFO" {
		t.Errorf("level = %q, want %q", gotLevel, "INFO")
	}
	if gotMessage != "test message" {
		t.Errorf("message = %q, want %q", gotMessage, "test message")
	}
}

func TestCallbackHandler_WithAttrs(t *testing.T) {
	h := &callbackHandler{level: slog.LevelInfo}
	got := h.WithAttrs([]slog.Attr{slog.String("key", "val")})
	if got != h {
		t.Error("WithAttrs should return same handler")
	}
}

func TestCallbackHandler_WithGroup(t *testing.T) {
	h := &callbackHandler{level: slog.LevelInfo}
	got := h.WithGroup("test")
	if got != h {
		t.Error("WithGroup should return same handler")
	}
}

// ──────── Client.Stop idempotent ────────

func TestClient_Stop_Idempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		ctx:    ctx,
		cancel: cancel,
	}
	c.mode.Store("balanced")

	c.Stop()
	// Second stop should not panic.
	c.Stop()
}

func TestClient_Stop_WithTunStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopCalled := false
	c := &Client{
		ctx:    ctx,
		cancel: cancel,
		stopTun: func() {
			stopCalled = true
		},
	}
	c.mode.Store("balanced")

	c.Stop()
	if !stopCalled {
		t.Error("stopTun was not called")
	}
}

// ──────── Stats edge cases ────────

func TestClient_Stats_NilMode(t *testing.T) {
	c := &Client{}
	// mode not stored — atomic.Value Load returns nil
	s := c.Stats()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		t.Fatalf("Stats() returned invalid JSON: %v\nraw: %s", err, s)
	}
	if result["mode"] != "balanced" {
		t.Errorf("mode = %v, want 'balanced' (default)", result["mode"])
	}
}

func TestClient_Stats_AllFields(t *testing.T) {
	c := &Client{
		started: time.Now().Add(-10 * time.Second),
	}
	c.mode.Store("stealth")

	s := c.Stats()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		t.Fatalf("Stats() returned invalid JSON: %v", err)
	}
	if result["mode"] != "stealth" {
		t.Errorf("mode = %v, want 'stealth'", result["mode"])
	}
	if result["connected"] != false {
		t.Errorf("connected = %v, want false", result["connected"])
	}
	uptime, ok := result["uptime_sec"].(float64)
	if !ok || uptime < 9 {
		t.Errorf("uptime_sec = %v, want >= 9", result["uptime_sec"])
	}
}

// ──────── muxStatsAdapter ────────

func TestMuxStatsAdapter(t *testing.T) {
	stats := mux.MuxStats{
		ActiveStreams: 5,
		BytesSent:     12345,
		BytesRecv:     67890,
	}
	adapter := &muxStatsAdapter{
		getMuxStats: func() mux.MuxStats { return stats },
	}

	if got := adapter.ActiveStreamCount(); got != 5 {
		t.Errorf("ActiveStreamCount() = %d, want 5", got)
	}
	if got := adapter.TotalBytesSent(); got != 12345 {
		t.Errorf("TotalBytesSent() = %d, want 12345", got)
	}
	if got := adapter.TotalBytesRecv(); got != 67890 {
		t.Errorf("TotalBytesRecv() = %d, want 67890", got)
	}
}

// ──────── loadEmbeddedProfile detailed ────────

func TestLoadEmbeddedProfile_Details(t *testing.T) {
	p, err := loadEmbeddedProfile()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Timing distribution
	if p.TimingDist.Type != "lognormal" {
		t.Errorf("TimingDist.Type = %q, want %q", p.TimingDist.Type, "lognormal")
	}
	if len(p.TimingDist.Params) != 2 {
		t.Errorf("TimingDist.Params len = %d, want 2", len(p.TimingDist.Params))
	}

	// Burst config
	if p.BurstConf.MinBurstBytes == 0 {
		t.Error("BurstConf.MinBurstBytes = 0, want nonzero")
	}
	if p.BurstConf.MaxBurstBytes == 0 {
		t.Error("BurstConf.MaxBurstBytes = 0, want nonzero")
	}
	if p.BurstConf.MinPauseMs == 0 {
		t.Error("BurstConf.MinPauseMs = 0, want nonzero")
	}
	if p.BurstConf.MaxPauseMs == 0 {
		t.Error("BurstConf.MaxPauseMs = 0, want nonzero")
	}
}

// ──────── parseMobileConfig additional cases ────────

func TestParseMobileConfig_AllFieldsRoundTrip(t *testing.T) {
	cfg, err := parseMobileConfig(validConfigJSON())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerPublicKey != strings.Repeat("ab", 32) {
		t.Errorf("ServerPublicKey = %q, want %q", cfg.ServerPublicKey, strings.Repeat("ab", 32))
	}
	if cfg.ClientPrivateKey != strings.Repeat("cd", 32) {
		t.Errorf("ClientPrivateKey = %q, want %q", cfg.ClientPrivateKey, strings.Repeat("cd", 32))
	}
}

func TestParseMobileConfig_OptionalDefaults(t *testing.T) {
	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	got, err := parseMobileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.ShapingMode != "" {
		t.Errorf("ShapingMode = %q, want empty", got.ShapingMode)
	}
	if got.AutoMode != false {
		t.Error("AutoMode = true, want false")
	}
	if got.LogLevel != "" {
		t.Errorf("LogLevel = %q, want empty", got.LogLevel)
	}
}

// ──────── decodeKey additional cases ────────

func TestDecodeKey_EmptyString(t *testing.T) {
	_, err := decodeKey("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestDecodeKey_TooLong(t *testing.T) {
	_, err := decodeKey(strings.Repeat("ab", 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error = %q, want it to mention 32 bytes", err)
	}
}

// ──────── SetMode with autoMode ────────

func TestClient_SetMode_WithAutoMode(t *testing.T) {
	c := &Client{autoMode: true, selProxy: &selectorProxy{sel: shaping.NewAdaptiveSelector(shaping.ModeBalanced, true)}}
	c.mode.Store("balanced")

	c.SetMode("stealth")
	if got := c.mode.Load().(string); got != "stealth" {
		t.Errorf("mode = %q, want 'stealth'", got)
	}
	if c.selProxy == nil {
		t.Error("selProxy is nil after SetMode")
	}
}

// ──────── SetLogCallback concurrency ────────

func TestSetLogCallback_Concurrent(t *testing.T) {
	logCBMu.Lock()
	origCB := logCB
	logCBMu.Unlock()
	defer func() {
		logCBMu.Lock()
		logCB = origCB
		logCBMu.Unlock()
	}()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb := &testLogCallback{fn: func(level, message string) {}}
			SetLogCallback(cb)
		}()
	}
	wg.Wait()
}

// ──────── setupNetstack stub (non-linux) ────────

func TestSetupNetstack_Stub(t *testing.T) {
	_, err := setupNetstack(context.Background(), nil, 1500, nil)
	if err == nil {
		t.Fatal("expected error from stub setupNetstack on non-linux")
	}
	// On non-Linux: stub returns "not supported".
	// On Linux: real implementation fails (e.g., bad fd) since we pass nil/0 args.
	errStr := err.Error()
	if !strings.Contains(errStr, "not supported") && !strings.Contains(errStr, "fdbased") {
		t.Errorf("error = %q, want it to contain 'not supported' or 'fdbased'", errStr)
	}
}

// ──────── Start() early error paths ────────

func TestStart_InvalidJSON(t *testing.T) {
	_, err := Start(0, "{bad json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "ghost.Start") {
		t.Errorf("error = %q, want ghost.Start prefix", err)
	}
}

func TestStart_MissingServerAddr(t *testing.T) {
	cfg := `{"server_sni": "x", "server_public_key": "` + strings.Repeat("ab", 32) + `", "client_private_key": "` + strings.Repeat("cd", 32) + `"}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error for missing server_addr")
	}
	if !strings.Contains(err.Error(), "server_addr") {
		t.Errorf("error = %q, want to mention server_addr", err)
	}
}

func TestStart_InvalidServerKey(t *testing.T) {
	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "not-hex",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error for invalid server key")
	}
	if !strings.Contains(err.Error(), "server_public_key") {
		t.Errorf("error = %q, want to mention server_public_key", err)
	}
}

func TestStart_InvalidClientKey(t *testing.T) {
	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "bad"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error for invalid client key")
	}
	if !strings.Contains(err.Error(), "client_private_key") {
		t.Errorf("error = %q, want to mention client_private_key", err)
	}
}

func TestStart_ServerKeyWrongLength(t *testing.T) {
	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "abcd",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error for wrong-length server key")
	}
	if !strings.Contains(err.Error(), "server_public_key") {
		t.Errorf("error = %q, want to mention server_public_key", err)
	}
}

func TestStart_WithLogCallback(t *testing.T) {
	// Ensure the logging path with a callback is exercised in Start.
	logCBMu.Lock()
	origCB := logCB
	logCBMu.Unlock()
	defer func() {
		logCBMu.Lock()
		logCB = origCB
		logCBMu.Unlock()
	}()

	SetLogCallback(&testLogCallback{fn: func(level, message string) {}})

	// This will still fail (invalid key), but exercises the cb != nil branch
	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "zzzz",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStart_WithNoLogCallback(t *testing.T) {
	// Exercises the cb == nil branch (stderr handler).
	logCBMu.Lock()
	origCB := logCB
	logCB = nil
	logCBMu.Unlock()
	defer func() {
		logCBMu.Lock()
		logCB = origCB
		logCBMu.Unlock()
	}()

	cfg := `{
		"server_addr": "1.2.3.4:443",
		"server_sni": "example.com",
		"server_public_key": "zzzz",
		"client_private_key": "` + strings.Repeat("cd", 32) + `"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStart_ValidKeysButConnectFails(t *testing.T) {
	// Valid keys, but server_addr is unreachable.
	// This exercises: config parsing, logging setup, key decoding,
	// auth creation, dialer creation, shaping profile loading,
	// shaping component setup, ConnManager creation.
	// ConnManager.Start will fail because the server is unreachable.
	cfg := `{
		"server_addr": "127.0.0.1:1",
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "` + strings.Repeat("cd", 32) + `",
		"shaping_mode": "stealth",
		"auto_mode": true,
		"log_level": "error"
	}`
	_, err := Start(0, cfg)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "ghost.Start") {
		t.Errorf("error = %q, want ghost.Start prefix", err)
	}
}

func TestStart_EmptyShapingMode(t *testing.T) {
	// Exercises the default shaping mode path.
	cfg := `{
		"server_addr": "127.0.0.1:1",
		"server_sni": "example.com",
		"server_public_key": "` + strings.Repeat("ab", 32) + `",
		"client_private_key": "` + strings.Repeat("cd", 32) + `",
		"shaping_mode": "",
		"log_level": "debug"
	}`
	_, err := Start(0, cfg)
	// Will fail at connection, but exercises empty mode path.
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// ──────── Client Stop with mgr ────────

func TestClient_Stop_Full(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tunStopCalled := false
	r, _, _ := os.Pipe()
	c := &Client{
		ctx:     ctx,
		cancel:  cancel,
		tunFile: r,
		stopTun: func() {
			tunStopCalled = true
		},
	}
	c.mode.Store("balanced")

	c.Stop()
	if !tunStopCalled {
		t.Error("stopTun was not called")
	}
	// Verify cancel was nil-ed
	if c.cancel != nil {
		t.Error("cancel should be nil after Stop")
	}
	// tunFile should have been closed
	if err := r.Close(); err == nil {
		t.Error("tunFile should already be closed")
	}
}
