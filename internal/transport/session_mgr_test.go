package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockAddr implements net.Addr for testing.
type mockAddr struct{ addr string }

func (a mockAddr) Network() string { return "tcp" }
func (a mockAddr) String() string  { return a.addr }

// mockPipeline is a closable pipeline for testing.
type mockPipeline struct {
	closed atomic.Bool
}

func (p *mockPipeline) Close() error {
	p.closed.Store(true)
	return nil
}

func newTestManager(max int, idle time.Duration) *SessionManager {
	return NewSessionManager(max, idle, slog.Default())
}

func TestSessionManager_RegisterAndCount(t *testing.T) {
	sm := newTestManager(10, 0)

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", sm.Count())
	}

	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("sess-%d", i)
		err := sm.Register(id, mockAddr{"1.2.3.4:100"}, &mockPipeline{}, nil)
		if err != nil {
			t.Fatalf("Register(%q) error: %v", id, err)
		}
	}

	if sm.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", sm.Count())
	}
}

func TestSessionManager_RegisterMaxSessions(t *testing.T) {
	sm := newTestManager(2, 0)

	if err := sm.Register("a", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := sm.Register("b", mockAddr{"1.2.3.4:2"}, &mockPipeline{}, nil); err != nil {
		t.Fatal(err)
	}

	err := sm.Register("c", mockAddr{"1.2.3.4:3"}, &mockPipeline{}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding maxSessions")
	}
	if !errors.Is(err, ErrMaxSessions) {
		t.Fatalf("error = %v, want ErrMaxSessions", err)
	}
	if sm.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", sm.Count())
	}
}

func TestSessionManager_RemoveCallsCleanup(t *testing.T) {
	sm := newTestManager(10, 0)
	pipe := &mockPipeline{}
	var cleanedUp atomic.Bool

	err := sm.Register("sess-1", mockAddr{"1.2.3.4:1"}, pipe, func() {
		cleanedUp.Store(true)
	})
	if err != nil {
		t.Fatal(err)
	}

	sm.Remove("sess-1")

	if !cleanedUp.Load() {
		t.Error("cleanup function was not called")
	}
	if !pipe.closed.Load() {
		t.Error("pipeline was not closed")
	}
	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", sm.Count())
	}
}

func TestSessionManager_RemoveUnknownID(t *testing.T) {
	sm := newTestManager(10, 0)
	// Should not panic.
	sm.Remove("nonexistent")
}

func TestSessionManager_Touch(t *testing.T) {
	sm := newTestManager(10, 0)

	err := sm.Register("sess-1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	s := sm.Get("sess-1")
	if s == nil {
		t.Fatal("Get returned nil")
	}
	before := s.lastActive

	time.Sleep(5 * time.Millisecond)
	sm.Touch("sess-1")

	s = sm.Get("sess-1")
	if !s.lastActive.After(before) {
		t.Error("Touch did not update lastActive")
	}
}

func TestSessionManager_CleanupIdleSessions(t *testing.T) {
	sm := newTestManager(10, 50*time.Millisecond)

	err := sm.Register("idle", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = sm.Register("active", mockAddr{"1.2.3.4:2"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for idle to become idle.
	time.Sleep(60 * time.Millisecond)

	// Touch active so it stays alive.
	sm.Touch("active")

	sm.Cleanup(context.Background())

	if sm.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", sm.Count())
	}
	if sm.Get("idle") != nil {
		t.Error("idle session should have been cleaned up")
	}
	if sm.Get("active") == nil {
		t.Error("active session should still exist")
	}
}

func TestSessionManager_CleanupCallsCleanupFunc(t *testing.T) {
	sm := newTestManager(10, 10*time.Millisecond)
	var cleanedUp atomic.Bool

	err := sm.Register("sess-1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, func() {
		cleanedUp.Store(true)
	})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)
	sm.Cleanup(context.Background())

	if !cleanedUp.Load() {
		t.Error("cleanup function was not called during Cleanup")
	}
}

func TestSessionManager_RunCleanupLoop(t *testing.T) {
	sm := newTestManager(10, 20*time.Millisecond)

	err := sm.Register("sess-1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go sm.RunCleanupLoop(ctx, 30*time.Millisecond)

	// Wait enough time for idle timeout + at least one cleanup tick.
	time.Sleep(120 * time.Millisecond)

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0 after cleanup loop", sm.Count())
	}

	cancel()
}

func TestSessionManager_Concurrent(t *testing.T) {
	sm := newTestManager(0, 0) // unlimited
	const n = 50

	var wg sync.WaitGroup

	// Concurrent Register.
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", i)
			_ = sm.Register(id, mockAddr{fmt.Sprintf("1.2.3.4:%d", i)}, &mockPipeline{}, nil)
		}(i)
	}
	wg.Wait()

	if sm.Count() != n {
		t.Fatalf("Count() = %d, want %d after concurrent register", sm.Count(), n)
	}

	// Concurrent Touch.
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			sm.Touch(fmt.Sprintf("sess-%d", i))
		}(i)
	}
	wg.Wait()

	// Concurrent Remove.
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			sm.Remove(fmt.Sprintf("sess-%d", i))
		}(i)
	}
	wg.Wait()

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0 after concurrent remove", sm.Count())
	}
}

func TestSessionManager_Get(t *testing.T) {
	sm := newTestManager(10, 0)
	addr := mockAddr{"5.6.7.8:999"}

	err := sm.Register("s1", addr, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	s := sm.Get("s1")
	if s == nil {
		t.Fatal("Get returned nil for registered session")
	}
	if s.id != "s1" {
		t.Errorf("id = %q, want %q", s.id, "s1")
	}
	if s.remoteAddr.String() != "5.6.7.8:999" {
		t.Errorf("remoteAddr = %q, want %q", s.remoteAddr.String(), "5.6.7.8:999")
	}

	if sm.Get("nonexistent") != nil {
		t.Error("Get should return nil for unknown id")
	}
}

func TestSessionManager_UnlimitedSessions(t *testing.T) {
	sm := newTestManager(0, 0) // 0 = unlimited

	for i := 0; i < 100; i++ {
		err := sm.Register(fmt.Sprintf("s-%d", i), mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
		if err != nil {
			t.Fatalf("Register failed at %d: %v", i, err)
		}
	}

	if sm.Count() != 100 {
		t.Fatalf("Count() = %d, want 100", sm.Count())
	}
}

func TestSessionManager_NilLogger(t *testing.T) {
	// Should not panic with nil logger.
	sm := NewSessionManager(10, time.Minute, nil)
	if err := sm.Register("s1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil); err != nil {
		t.Fatal(err)
	}
	sm.Touch("s1")
	sm.Remove("s1")
}

func TestSessionManager_NilCleanupAndPipeline(t *testing.T) {
	sm := newTestManager(10, 0)

	// Register with nil cleanup and nil pipeline.
	err := sm.Register("s1", mockAddr{"1.2.3.4:1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Remove should not panic.
	sm.Remove("s1")
}

func TestSessionManager_CleanupNoTimeout(t *testing.T) {
	sm := newTestManager(10, 0) // 0 = no timeout

	err := sm.Register("s1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	sm.Cleanup(context.Background())

	// Session should still be there since idle timeout is 0.
	if sm.Count() != 1 {
		t.Fatalf("Count() = %d, want 1 (no timeout means no cleanup)", sm.Count())
	}
}

func TestSessionManager_RemoveNotFoundIsNoop(t *testing.T) {
	sm := newTestManager(10, 0)

	// Register one session.
	err := sm.Register("s1", mockAddr{"1.2.3.4:1"}, &mockPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Double-remove should be safe.
	sm.Remove("s1")
	sm.Remove("s1")

	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", sm.Count())
	}
}

// TestSessionManager_NilPipelineRemove verifies that the Remove path
// handles the case where pipeline is nil without panicking.
func TestSessionManager_NilPipelineRemove(t *testing.T) {
	sm := newTestManager(10, time.Millisecond)
	var called atomic.Bool

	err := sm.Register("np", mockAddr{"1.2.3.4:1"}, nil, func() { called.Store(true) })
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Millisecond)
	sm.Cleanup(context.Background())

	if !called.Load() {
		t.Error("cleanup func should have been called even with nil pipeline")
	}
	if sm.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", sm.Count())
	}
}

// netPipeAddr returns a suitable net.Addr for testing.
func netPipeAddr() net.Addr {
	return mockAddr{"test:0"}
}
