package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ErrMaxSessions is returned by Register when the maximum number of concurrent
// sessions has been reached.
var ErrMaxSessions = errors.New("maximum sessions reached")

// SessionManager tracks active authenticated client sessions.
type SessionManager struct {
	mu          sync.RWMutex
	sessions    map[string]*managedSession
	maxSessions int
	idleTimeout time.Duration
	log         *slog.Logger
}

type managedSession struct {
	id         string
	remoteAddr net.Addr
	created    time.Time
	lastActive time.Time
	pipeline   interface{ Close() error }
	cleanup    func()
}

// NewSessionManager creates a SessionManager.
// maxSessions is the maximum number of concurrent sessions (0 = unlimited).
// idleTimeout is the duration after which an idle session is cleaned up (0 = no timeout).
func NewSessionManager(maxSessions int, idleTimeout time.Duration, log *slog.Logger) *SessionManager {
	if log == nil {
		log = slog.Default()
	}
	return &SessionManager{
		sessions:    make(map[string]*managedSession),
		maxSessions: maxSessions,
		idleTimeout: idleTimeout,
		log:         log,
	}
}

// Register adds a new authenticated session. Returns ErrMaxSessions if maxSessions
// has been reached. pipeline is the closeable resource (e.g. mux pipeline).
// cleanup is called on Remove to stop per-session goroutines.
func (sm *SessionManager) Register(id string, addr net.Addr, pipeline interface{ Close() error }, cleanup func()) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.maxSessions > 0 && len(sm.sessions) >= sm.maxSessions {
		return fmt.Errorf("register session %s: %w", id, ErrMaxSessions)
	}

	now := time.Now()
	sm.sessions[id] = &managedSession{
		id:         id,
		remoteAddr: addr,
		created:    now,
		lastActive: now,
		pipeline:   pipeline,
		cleanup:    cleanup,
	}

	sm.log.Info("session registered",
		"session_id", id,
		"remote_addr", addr,
		"total_count", len(sm.sessions),
	)
	return nil
}

// Remove cleans up a session: calls cleanup(), closes pipeline, and removes it
// from the map. Safe to call multiple times or with an unknown id (no-op).
func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	s, ok := sm.sessions[id]
	if !ok {
		sm.mu.Unlock()
		return
	}
	delete(sm.sessions, id)
	sm.mu.Unlock()

	sm.teardown(s, "removed")
}

// Touch updates the lastActive timestamp for a session. Called on each client activity.
func (sm *SessionManager) Touch(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.sessions[id]; ok {
		s.lastActive = time.Now()
		sm.log.Debug("session touched", "session_id", id)
	}
}

// Cleanup removes all sessions that have been idle longer than idleTimeout.
// For each removed session, calls cleanup() and closes pipeline.
func (sm *SessionManager) Cleanup(ctx context.Context) {
	if sm.idleTimeout <= 0 {
		return
	}

	cutoff := time.Now().Add(-sm.idleTimeout)

	sm.mu.Lock()
	var expired []*managedSession
	for _, s := range sm.sessions {
		if s.lastActive.Before(cutoff) {
			expired = append(expired, s)
		}
	}
	for _, s := range expired {
		delete(sm.sessions, s.id)
	}
	remaining := len(sm.sessions)
	sm.mu.Unlock()

	for _, s := range expired {
		sm.teardown(s, "idle_timeout")
	}

	if len(expired) > 0 {
		sm.log.Info("session cleanup",
			"removed_count", len(expired),
			"remaining_count", remaining,
		)
	}
}

// Count returns the number of active sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// Get returns the managedSession for an id, or nil if not found.
func (sm *SessionManager) Get(id string) *managedSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// RunCleanupLoop runs Cleanup periodically until ctx is cancelled.
func (sm *SessionManager) RunCleanupLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.Cleanup(ctx)
		}
	}
}

// teardown calls cleanup and closes pipeline for a session, logging any errors.
func (sm *SessionManager) teardown(s *managedSession, reason string) {
	if s.cleanup != nil {
		s.cleanup()
	}
	if s.pipeline != nil {
		if err := s.pipeline.Close(); err != nil {
			sm.log.Warn("session pipeline close error",
				"session_id", s.id,
				"err", err,
			)
		}
	}
	sm.log.Info("session removed",
		"session_id", s.id,
		"reason", reason,
	)
}
