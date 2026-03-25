package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"ghost/internal/mux"
	"ghost/internal/transport"
)

// ErrNotConnected is returned by the StreamOpener when no pipeline is available.
var ErrNotConnected = errors.New("connmgr: not connected")

// ConnManagerConfig holds configuration for NewConnManager.
type ConnManagerConfig struct {
	Dialer        transport.Dialer
	ServerAddr    string
	ServerSNI     string
	Pipeline      PipelineOpts
	HealthCheck   time.Duration // interval between health checks (default 5s)
	FreezeTimeout time.Duration // no-data timeout for freeze detection (default 10s)
	MaxRetries    int           // 0 = unlimited
}

// PipelineOpts captures everything needed to create a pipeline.
type PipelineOpts struct {
	Wrap         *mux.PipelineWrap
	SharedSecret [32]byte
	// PostConnect is called after a new pipeline is created.
	// It receives the new pipeline and should wire up any per-pipeline
	// resources (CoverGenerator, StatsUpdater, etc).
	// Returns a cleanup function that is called when the pipeline is replaced.
	// May be nil if no post-connect wiring is needed.
	PostConnect func(p *mux.ClientPipeline) (cleanup func())
}

// ConnManager maintains a live Ghost pipeline and recreates it on failure.
// It provides a StreamOpener that is safe for concurrent use and survives
// pipeline recreation.
type ConnManager struct {
	cfg ConnManagerConfig

	mu              sync.RWMutex
	pipeline        *mux.ClientPipeline
	conn            transport.Conn
	pipelineCleanup func()
	healthy         bool

	backoff       *ExponentialBackoff
	reconnectCh   chan struct{}
	healthResetCh chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewConnManager creates a ConnManager with the given configuration.
// Call Start to establish the initial connection and begin the reconnect loop.
func NewConnManager(cfg ConnManagerConfig) *ConnManager {
	if cfg.HealthCheck == 0 {
		cfg.HealthCheck = 5 * time.Second
	}
	if cfg.FreezeTimeout == 0 {
		cfg.FreezeTimeout = 10 * time.Second
	}
	return &ConnManager{
		cfg: cfg,
		backoff: &ExponentialBackoff{
			Initial:    1 * time.Second,
			Max:        30 * time.Second,
			Multiplier: 2.0,
		},
		reconnectCh:   make(chan struct{}, 1),
		healthResetCh: make(chan struct{}, 1),
	}
}

// Start establishes the initial connection and starts the reconnect loop.
// Retries up to 3 times with 2 second intervals before returning an error.
func (cm *ConnManager) Start(ctx context.Context) error {
	cm.ctx, cm.cancel = context.WithCancel(ctx)

	const maxBootstrapAttempts = 3
	var err error
	for attempt := 1; attempt <= maxBootstrapAttempts; attempt++ {
		if err = cm.connect(); err == nil {
			break
		}
		slog.Warn("connmgr: bootstrap connect failed",
			"attempt", attempt,
			"max", maxBootstrapAttempts,
			"error", err,
		)
		if attempt < maxBootstrapAttempts {
			select {
			case <-ctx.Done():
				cm.cancel()
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	if err != nil {
		cm.cancel()
		return fmt.Errorf("connmgr: initial connect (after %d attempts): %w", maxBootstrapAttempts, err)
	}

	cm.wg.Add(1)
	go cm.reconnectLoop()

	cm.wg.Add(1)
	go cm.healthMonitor()

	return nil
}

// StreamOpener returns a StreamOpener closure that is safe for concurrent use.
// The returned opener delegates to the current pipeline and triggers reconnection
// on failure.
func (cm *ConnManager) StreamOpener() StreamOpener {
	return func(ctx context.Context, addr string, port uint16) (Stream, error) {
		cm.mu.RLock()
		p := cm.pipeline
		cm.mu.RUnlock()

		if p == nil {
			return nil, ErrNotConnected
		}

		s, err := p.Mux.Open(ctx, addr, port)
		if err != nil {
			cm.triggerReconnect()
			return nil, err
		}
		return s, nil
	}
}

// Stop shuts down the reconnect loop and closes the current pipeline.
func (cm *ConnManager) Stop() {
	cm.cancel()
	cm.wg.Wait()

	cm.mu.Lock()
	p := cm.pipeline
	cleanup := cm.pipelineCleanup
	cm.pipeline = nil
	cm.conn = nil
	cm.pipelineCleanup = nil
	cm.healthy = false
	cm.mu.Unlock()

	if p != nil {
		p.Close()
	}
	if cleanup != nil {
		cleanup()
	}
}

// Healthy reports whether the ConnManager currently has a working pipeline.
func (cm *ConnManager) Healthy() bool {
	cm.mu.RLock()
	h := cm.healthy
	cm.mu.RUnlock()
	return h
}

// connect dials the server and creates a new pipeline, replacing the old one.
func (cm *ConnManager) connect() error {
	conn, err := cm.cfg.Dialer.Dial(cm.ctx, cm.cfg.ServerAddr, cm.cfg.ServerSNI)
	if err != nil {
		return fmt.Errorf("connmgr: dial: %w", err)
	}

	upPath, downPath := mux.DerivePaths(cm.cfg.Pipeline.SharedSecret)

	p, err := mux.NewClientPipeline(cm.ctx, conn, upPath, downPath, cm.cfg.Pipeline.Wrap)
	if err != nil {
		conn.Close()
		return fmt.Errorf("connmgr: pipeline: %w", err)
	}

	var newCleanup func()
	if cm.cfg.Pipeline.PostConnect != nil {
		newCleanup = cm.cfg.Pipeline.PostConnect(p)
	}

	cm.mu.Lock()
	oldPipeline := cm.pipeline
	oldCleanup := cm.pipelineCleanup
	cm.pipeline = p
	cm.conn = conn
	cm.pipelineCleanup = newCleanup
	cm.healthy = true
	cm.mu.Unlock()

	// Reset health monitor state for new connection
	select {
	case cm.healthResetCh <- struct{}{}:
	default:
	}

	if oldPipeline != nil {
		oldPipeline.Close()
	}
	if oldCleanup != nil {
		oldCleanup()
	}

	return nil
}

// triggerReconnect signals the reconnect loop to attempt a new connection.
// Multiple calls coalesce into a single reconnect attempt.
func (cm *ConnManager) triggerReconnect() {
	cm.mu.Lock()
	cm.healthy = false
	cm.mu.Unlock()

	select {
	case cm.reconnectCh <- struct{}{}:
	default:
	}
}

// reconnectLoop waits for reconnect signals and attempts to re-establish the pipeline.
func (cm *ConnManager) reconnectLoop() {
	defer cm.wg.Done()
	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-cm.reconnectCh:
			cm.doReconnect()
		}
	}
}

// doReconnect performs the retry loop with exponential backoff.
func (cm *ConnManager) doReconnect() {
	cm.backoff.Reset()

	maxRetries := cm.cfg.MaxRetries
	for attempt := 1; maxRetries == 0 || attempt <= maxRetries; attempt++ {
		delay := cm.backoff.Next()

		select {
		case <-cm.ctx.Done():
			return
		case <-time.After(delay):
		}

		if err := cm.connect(); err != nil {
			slog.Warn("connmgr: reconnect failed",
				"attempt", attempt,
				"error", err,
			)
			continue
		}

		slog.Info("connmgr: reconnected", "attempt", attempt)
		cm.backoff.Reset()
		return
	}

	slog.Error("connmgr: reconnect retries exhausted", "max", maxRetries)
}
