package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghost/internal/auth"
	"ghost/internal/config"

	"gopkg.in/yaml.v3"
)

// ---------- Test 1: SessionManager full lifecycle ----------

func TestServerInfra_SessionLifecycle(t *testing.T) {
	sm := NewSessionManager(3, 500*time.Millisecond, nil)

	// Track cleanup calls per session.
	cleanups := make(map[string]*atomic.Bool)
	for i := 1; i <= 4; i++ {
		cleanups[fmt.Sprintf("s%d", i)] = &atomic.Bool{}
	}

	makeCleanup := func(id string) func() {
		return func() { cleanups[id].Store(true) }
	}

	// Register 3 sessions → all succeed.
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("s%d", i)
		err := sm.Register(id, mockAddr{"1.2.3.4:" + fmt.Sprint(i)}, &mockPipeline{}, makeCleanup(id))
		if err != nil {
			t.Fatalf("Register(%s) failed: %v", id, err)
		}
	}
	if sm.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", sm.Count())
	}

	// Register 4th → ErrMaxSessions.
	err := sm.Register("s4", mockAddr{"1.2.3.4:4"}, &mockPipeline{}, makeCleanup("s4"))
	if err == nil {
		t.Fatal("Register(s4) should have failed with ErrMaxSessions")
	}

	// Wait 400ms so sessions 2,3 become idle (but not yet past the 500ms threshold).
	time.Sleep(400 * time.Millisecond)

	// Touch session 1 to keep it alive.
	sm.Touch("s1")

	// Sleep another 200ms to push total past 500ms for s2,s3 but s1 was touched at ~400ms.
	time.Sleep(200 * time.Millisecond)

	// Cleanup → sessions 2,3 removed (idle >500ms), session 1 survives (touched at ~400ms, only ~200ms idle).
	sm.Cleanup(t.Context())

	if sm.Count() != 1 {
		t.Fatalf("Count() after cleanup = %d, want 1", sm.Count())
	}
	if sm.Get("s1") == nil {
		t.Error("s1 should survive (was touched)")
	}
	if sm.Get("s2") != nil {
		t.Error("s2 should have been cleaned up")
	}
	if sm.Get("s3") != nil {
		t.Error("s3 should have been cleaned up")
	}

	// Verify cleanup functions were called for removed sessions.
	if !cleanups["s2"].Load() {
		t.Error("s2 cleanup was not called")
	}
	if !cleanups["s3"].Load() {
		t.Error("s3 cleanup was not called")
	}
	if cleanups["s1"].Load() {
		t.Error("s1 cleanup should NOT have been called yet")
	}

	// Remove session 1 → cleanup called.
	sm.Remove("s1")
	if !cleanups["s1"].Load() {
		t.Error("s1 cleanup was not called after Remove")
	}

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", sm.Count())
	}
}

// ---------- Test 2: SessionManager concurrent safety ----------

func TestServerInfra_SessionConcurrency(t *testing.T) {
	sm := NewSessionManager(100, 0, nil)
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("c-%d", i)
			if err := sm.Register(id, mockAddr{fmt.Sprintf("10.0.0.%d:1", i)}, &mockPipeline{}, nil); err != nil {
				t.Errorf("Register(%s): %v", id, err)
				return
			}
			sm.Touch(id)
			sm.Remove(id)
		}(i)
	}
	wg.Wait()

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0 after concurrent ops", sm.Count())
	}
}

// ---------- Test 3: CertManager self-signed mode ----------

func TestServerInfra_CertManagerSelfSigned(t *testing.T) {
	cm, err := NewCertManager("infra.test", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "infra.test"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}

	// Verify cert subject matches domain.
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := x.VerifyHostname("infra.test"); err != nil {
		t.Errorf("VerifyHostname: %v", err)
	}

	// Verify TLSConfig NextProtos.
	tc := cm.TLSConfig()
	has := make(map[string]bool)
	for _, p := range tc.NextProtos {
		has[p] = true
	}
	if !has["h2"] {
		t.Error("TLSConfig missing h2")
	}
	if !has["http/1.1"] {
		t.Error("TLSConfig missing http/1.1")
	}
}

// ---------- Test 4: CertManager manual mode ----------

func TestServerInfra_CertManagerManual(t *testing.T) {
	// Generate initial cert.
	tlsCert1, err := GenerateSelfSignedCert("manual-infra.test")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	writeCertAndKey(t, certFile, keyFile, tlsCert1)

	cm, err := NewCertManager("manual-infra.test", false, "", "", certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.Mode() != "manual" {
		t.Fatalf("mode = %q, want manual", cm.Mode())
	}

	// Get initial cert.
	cert1, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "manual-infra.test"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	x1, _ := x509.ParseCertificate(cert1.Certificate[0])

	// Overwrite with a new cert.
	tlsCert2, _ := GenerateSelfSignedCert("manual-infra.test")
	writeCertAndKey(t, certFile, keyFile, tlsCert2)

	// Reload.
	if err := cm.ReloadCert(); err != nil {
		t.Fatalf("ReloadCert: %v", err)
	}

	// Verify new cert.
	cert2, _ := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "manual-infra.test"})
	x2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if x1.SerialNumber.Cmp(x2.SerialNumber) == 0 {
		t.Error("cert serial unchanged after reload — expected new cert")
	}
}

// ---------- Test 5: CertManager TLS config correctness ----------

func TestServerInfra_CertManagerTLSConfig(t *testing.T) {
	cm, err := NewCertManager("tlscheck.test", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	tc := cm.TLSConfig()

	// Verify NextProtos contains all required protocols.
	want := map[string]bool{"acme-tls/1": true, "h2": true, "http/1.1": true}
	for _, p := range tc.NextProtos {
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("missing NextProtos: %v", want)
	}

	// Verify MinVersion.
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", tc.MinVersion, tls.VersionTLS12)
	}

	// Verify GetCertificate is set.
	if tc.GetCertificate == nil {
		t.Error("GetCertificate callback not set")
	}
}

// ---------- Test 6: Config defaults and round-trip ----------

func TestServerInfra_ConfigDefaults(t *testing.T) {
	var cfg config.ServerConfig
	cfg.Defaults()

	// Verify critical defaults.
	if cfg.Listen != ":443" {
		t.Errorf("Listen = %q, want :443", cfg.Listen)
	}
	if cfg.Sessions.MaxSessions != 10 {
		t.Errorf("Sessions.MaxSessions = %d, want 10", cfg.Sessions.MaxSessions)
	}
	if cfg.Sessions.IdleTimeoutSec != 300 {
		t.Errorf("Sessions.IdleTimeoutSec = %d, want 300", cfg.Sessions.IdleTimeoutSec)
	}
	if cfg.Shaping.ProfilePath != "profiles/chrome_browsing.json" {
		t.Errorf("Shaping.ProfilePath = %q, want profiles/chrome_browsing.json", cfg.Shaping.ProfilePath)
	}
	if cfg.Fallback.Addr != "127.0.0.1:8080" {
		t.Errorf("Fallback.Addr = %q, want 127.0.0.1:8080", cfg.Fallback.Addr)
	}

	// Marshal to YAML → unmarshal → verify round-trip.
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var cfg2 config.ServerConfig
	if err := yaml.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if cfg2.Listen != cfg.Listen {
		t.Errorf("round-trip Listen = %q, want %q", cfg2.Listen, cfg.Listen)
	}
	if cfg2.Sessions.MaxSessions != cfg.Sessions.MaxSessions {
		t.Errorf("round-trip MaxSessions = %d, want %d", cfg2.Sessions.MaxSessions, cfg.Sessions.MaxSessions)
	}
	if cfg2.Sessions.IdleTimeoutSec != cfg.Sessions.IdleTimeoutSec {
		t.Errorf("round-trip IdleTimeoutSec = %d, want %d", cfg2.Sessions.IdleTimeoutSec, cfg.Sessions.IdleTimeoutSec)
	}
	if cfg2.Shaping.ProfilePath != cfg.Shaping.ProfilePath {
		t.Errorf("round-trip ProfilePath = %q, want %q", cfg2.Shaping.ProfilePath, cfg.Shaping.ProfilePath)
	}
	if cfg2.Fallback.Addr != cfg.Fallback.Addr {
		t.Errorf("round-trip Fallback.Addr = %q, want %q", cfg2.Fallback.Addr, cfg.Fallback.Addr)
	}
}

// ---------- Test 7: Keygen produces valid keys ----------

func TestServerInfra_KeygenIntegration(t *testing.T) {
	kp1, err := auth.GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair 1: %v", err)
	}
	kp2, err := auth.GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair 2: %v", err)
	}

	ss1, err := auth.SharedSecret(kp1.Private, kp2.Public)
	if err != nil {
		t.Fatalf("SharedSecret(kp1.Priv, kp2.Pub): %v", err)
	}
	ss2, err := auth.SharedSecret(kp2.Private, kp1.Public)
	if err != nil {
		t.Fatalf("SharedSecret(kp2.Priv, kp1.Pub): %v", err)
	}

	if ss1 != ss2 {
		t.Fatal("shared secrets don't match — x25519 key agreement broken")
	}

	// Verify the shared secret is non-zero.
	var zero [32]byte
	if ss1 == zero {
		t.Fatal("shared secret is all zeros")
	}
}

// ---------- Coverage boost tests ----------

func TestServerInfra_SetCertManager(t *testing.T) {
	cm, err := NewCertManager("set.test", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cfg := &config.ServerConfig{}
	cfg.Defaults()
	cert, _ := GenerateSelfSignedCert("set.test")
	sa, _ := auth.NewServerAuth([32]byte{}, nil)
	srv := NewServer(cfg, cert, sa, nil)
	gs := srv.(*ghostServer)
	gs.SetCertManager(cm)

	if gs.certMgr != cm {
		t.Error("certMgr not set")
	}
	if gs.tlsConfig == nil {
		t.Error("tlsConfig not updated")
	}
}

func TestServerInfra_SingleConnListenerAddr(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := newSingleConnListener(c1)
	addr := ln.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}
}

func TestServerInfra_CertManagerFileWatcherCancels(t *testing.T) {
	// Generate cert files for manual mode.
	cert, _ := GenerateSelfSignedCert("watch.test")
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	writeCertAndKey(t, certFile, keyFile, cert)

	cm, err := NewCertManager("watch.test", false, "", "", certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// StartFileWatcher should return immediately when context is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	cm.StartFileWatcher(ctx)
	// No hang = pass.
}

func TestServerInfra_CertManagerFileWatcherNoop(t *testing.T) {
	// Self-signed mode — StartFileWatcher should be a no-op.
	cm, err := NewCertManager("noop.test", false, "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	cm.StartFileWatcher(context.Background())
	// Should return immediately (no goroutine started).
}
