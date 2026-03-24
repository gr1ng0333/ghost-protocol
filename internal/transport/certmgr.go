package transport

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// CertManager handles TLS certificate lifecycle.
// Supports three modes: autocert (Let's Encrypt), manual cert files, and self-signed.
type CertManager struct {
	mode   string // "autocert", "manual", "selfsigned"
	domain string

	// autocert mode
	manager *autocert.Manager

	// manual/selfsigned mode: hot-reloadable cert
	mu       sync.RWMutex
	cert     *tls.Certificate
	certFile string
	keyFile  string

	log *slog.Logger
}

// NewCertManager creates a CertManager based on config fields.
// If autoCert is true, sets up Let's Encrypt with HTTP-01 + TLS-ALPN-01.
// If certFile and keyFile are set, loads cert from files (manual mode).
// Otherwise, generates a self-signed cert for the domain.
func NewCertManager(domain string, autoCert bool, email, cacheDir, certFile, keyFile string, log *slog.Logger) (*CertManager, error) {
	if log == nil {
		log = slog.Default()
	}

	if autoCert {
		return newAutoCertManager(domain, email, cacheDir, log), nil
	}

	if certFile != "" && keyFile != "" {
		return newManualCertManager(domain, certFile, keyFile, log)
	}

	return newSelfSignedCertManager(domain, log)
}

func newAutoCertManager(domain, email, cacheDir string, log *slog.Logger) *CertManager {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Cache:      autocert.DirCache(cacheDir),
	}
	log.Info("certmgr: autocert mode", "domain", domain, "email", email, "cache", cacheDir)
	return &CertManager{
		mode:    "autocert",
		domain:  domain,
		manager: m,
		log:     log,
	}
}

func newManualCertManager(domain, certFile, keyFile string, log *slog.Logger) (*CertManager, error) {
	cm := &CertManager{
		mode:     "manual",
		domain:   domain,
		certFile: certFile,
		keyFile:  keyFile,
		log:      log,
	}
	if err := cm.ReloadCert(); err != nil {
		return nil, err
	}
	log.Info("certmgr: manual mode", "domain", domain, "cert", certFile, "key", keyFile)
	return cm, nil
}

func newSelfSignedCertManager(domain string, log *slog.Logger) (*CertManager, error) {
	cert, err := GenerateSelfSignedCert(domain)
	if err != nil {
		return nil, err
	}
	log.Info("certmgr: self-signed mode", "domain", domain)
	return &CertManager{
		mode:   "selfsigned",
		domain: domain,
		cert:   &cert,
		log:    log,
	}, nil
}

// GetCertificate is the tls.Config.GetCertificate callback.
// Works for all three modes.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cm.mode == "autocert" {
		return cm.manager.GetCertificate(hello)
	}
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cert, nil
}

// TLSConfig returns a tls.Config configured for this CertManager.
// Includes correct NextProtos for ACME TLS-ALPN-01 + h2 + http/1.1.
func (cm *CertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cm.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
		MinVersion:     tls.VersionTLS12,
	}
}

// HTTPHandler returns an http.Handler for ACME HTTP-01 challenges on :80.
// Returns nil if not in autocert mode.
// Non-challenge requests get redirected to HTTPS.
func (cm *CertManager) HTTPHandler() http.Handler {
	if cm.mode != "autocert" {
		return nil
	}
	return cm.manager.HTTPHandler(nil)
}

// ReloadCert reloads certificate from disk (manual mode only).
func (cm *CertManager) ReloadCert() error {
	if cm.mode != "manual" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err != nil {
		return err
	}
	cm.mu.Lock()
	cm.cert = &cert
	cm.mu.Unlock()
	cm.log.Info("certmgr: certificate reloaded", "cert", cm.certFile)
	return nil
}

// StartFileWatcher starts a goroutine that reloads cert when files change.
// Uses polling (check every 12 hours). Only active in manual mode.
func (cm *CertManager) StartFileWatcher(ctx context.Context) {
	if cm.mode != "manual" {
		return
	}
	go cm.watchLoop(ctx)
}

func (cm *CertManager) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	var lastMod time.Time
	if info, err := os.Stat(cm.certFile); err == nil {
		lastMod = info.ModTime()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(cm.certFile)
			if err != nil {
				cm.log.Warn("certmgr: stat cert file", "err", err)
				continue
			}
			if info.ModTime().After(lastMod) {
				if err := cm.ReloadCert(); err != nil {
					cm.log.Error("certmgr: reload failed", "err", err)
				} else {
					lastMod = info.ModTime()
				}
			}
		}
	}
}

// Mode returns the current certificate management mode.
func (cm *CertManager) Mode() string {
	return cm.mode
}
