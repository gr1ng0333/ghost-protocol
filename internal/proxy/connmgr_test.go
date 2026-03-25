package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghost/internal/mux"
	"ghost/internal/transport"
)

// waitFor polls cond every 50ms until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if cond() {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// newConnMgrDialer creates a mockDialer that tracks dial count and returns
// fresh mockConns (alive=true) on each call after the first. The first call
// returns the provided firstConn.
func newConnMgrDialer(firstConn *mockConn, dialCount *atomic.Int32) *mockDialer {
	return &mockDialer{
		dialFunc: func(ctx context.Context, addr, sni string) (transport.Conn, error) {
			n := dialCount.Add(1)
			if n == 1 {
				return firstConn, nil
			}
			mc := &mockConn{}
			mc.alive.Store(true)
			return mc, nil
		},
	}
}

func TestConnManager_InitialConnect(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:      newConnMgrDialer(mc, &dialCount),
		ServerAddr:  "127.0.0.1:443",
		ServerSNI:   "example.com",
		HealthCheck: 100 * time.Millisecond,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	if !cm.Healthy() {
		t.Fatal("expected Healthy() == true after Start")
	}
	if dialCount.Load() != 1 {
		t.Fatalf("expected 1 dial, got %d", dialCount.Load())
	}
}

func TestConnManager_InitialConnectFails(t *testing.T) {
	dialErr := errors.New("connection refused")
	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, addr, sni string) (transport.Conn, error) {
			return nil, dialErr
		},
	}

	cm := NewConnManager(ConnManagerConfig{
		Dialer:     dialer,
		ServerAddr: "127.0.0.1:443",
		ServerSNI:  "example.com",
	})

	err := cm.Start(context.Background())
	if err == nil {
		cm.Stop()
		t.Fatal("expected Start to return error")
	}
	if !errors.Is(err, dialErr) {
		t.Fatalf("expected wrapped dialErr, got: %v", err)
	}
}

func TestConnManager_StreamOpener_Works(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:      newConnMgrDialer(mc, &dialCount),
		ServerAddr:  "127.0.0.1:443",
		ServerSNI:   "example.com",
		HealthCheck: 5 * time.Second,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	opener := cm.StreamOpener()
	_, err := opener(context.Background(), "example.com", 443)
	// Mux.Open may succeed or fail with mock — either is fine.
	// The key assertion: it must NOT return ErrNotConnected.
	if errors.Is(err, ErrNotConnected) {
		t.Fatal("got ErrNotConnected — pipeline should exist after Start")
	}
}

func TestConnManager_StreamOpener_WhenNotConnected(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:      newConnMgrDialer(mc, &dialCount),
		ServerAddr:  "127.0.0.1:443",
		ServerSNI:   "example.com",
		HealthCheck: 5 * time.Second,
	})

	// Don't call Start — pipeline is nil.
	opener := cm.StreamOpener()
	_, err := opener(context.Background(), "example.com", 443)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got: %v", err)
	}
}

func TestConnManager_Reconnect_OnDeadConnection(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:        newConnMgrDialer(mc, &dialCount),
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   100 * time.Millisecond,
		FreezeTimeout: 10 * time.Second,
		MaxRetries:    0,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	// Kill the connection.
	mc.alive.Store(false)

	// Wait for reconnect: dial count should reach 2+ and Healthy should restore.
	if !waitFor(t, 5*time.Second, func() bool { return dialCount.Load() >= 2 }) {
		t.Fatalf("timed out waiting for reconnect; dial count = %d", dialCount.Load())
	}
	if !waitFor(t, 3*time.Second, func() bool { return cm.Healthy() }) {
		t.Fatal("expected Healthy() == true after reconnect")
	}
}

func TestConnManager_Reconnect_StreamsResumeAfterReconnect(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:        newConnMgrDialer(mc, &dialCount),
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   100 * time.Millisecond,
		FreezeTimeout: 10 * time.Second,
		MaxRetries:    0,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	// Kill the connection and wait for reconnect.
	mc.alive.Store(false)
	if !waitFor(t, 5*time.Second, func() bool { return dialCount.Load() >= 2 && cm.Healthy() }) {
		t.Fatalf("timed out waiting for reconnect")
	}

	// After reconnect, StreamOpener should not return ErrNotConnected.
	opener := cm.StreamOpener()
	_, err := opener(context.Background(), "example.com", 443)
	if errors.Is(err, ErrNotConnected) {
		t.Fatal("got ErrNotConnected after reconnect — pipeline should be restored")
	}
	// Error from Mux.Open is fine (no real server), but not ErrNotConnected.
}

func TestConnManager_GracefulStop(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:      newConnMgrDialer(mc, &dialCount),
		ServerAddr:  "127.0.0.1:443",
		ServerSNI:   "example.com",
		HealthCheck: 50 * time.Millisecond,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	done := make(chan struct{})
	go func() {
		cm.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return in time")
	}

	if cm.Healthy() {
		t.Fatal("expected Healthy() == false after Stop")
	}

	opener := cm.StreamOpener()
	_, err := opener(context.Background(), "example.com", 443)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected after Stop, got: %v", err)
	}
}

func TestConnManager_ConcurrentStreamOpener(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	cm := NewConnManager(ConnManagerConfig{
		Dialer:        newConnMgrDialer(mc, &dialCount),
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   100 * time.Millisecond,
		FreezeTimeout: 10 * time.Second,
		MaxRetries:    0,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	opener := cm.StreamOpener()

	const goroutines = 20
	const calls = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				_, err := opener(context.Background(), "example.com", 443)
				// Every call should return either a mux error or ErrNotConnected.
				// It must never panic.
				if err == nil {
					// Unexpected success with no real server, but not a failure.
					continue
				}
			}
		}()
	}

	// Meanwhile, toggle alive to cause reconnection churn.
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond)
			mc.alive.Store(false)
			time.Sleep(50 * time.Millisecond)
			mc.alive.Store(true)
		}
	}()

	wg.Wait()
	// If we reach here without panic or race, the test passes.
}

func TestConnManager_PostConnectCalled(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialCount atomic.Int32
	var postConnectCount atomic.Int32
	var cleanupCount atomic.Int32

	cm := NewConnManager(ConnManagerConfig{
		Dialer:        newConnMgrDialer(mc, &dialCount),
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   100 * time.Millisecond,
		FreezeTimeout: 10 * time.Second,
		MaxRetries:    0,
		Pipeline: PipelineOpts{
			PostConnect: func(p *mux.ClientPipeline) (cleanup func()) {
				postConnectCount.Add(1)
				return func() {
					cleanupCount.Add(1)
				}
			},
		},
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	if postConnectCount.Load() != 1 {
		t.Fatalf("expected PostConnect called once on initial connect, got %d", postConnectCount.Load())
	}

	// Trigger reconnect by killing connection.
	mc.alive.Store(false)

	if !waitFor(t, 5*time.Second, func() bool { return postConnectCount.Load() >= 2 }) {
		t.Fatalf("timed out waiting for PostConnect on reconnect; count = %d", postConnectCount.Load())
	}

	// Cleanup for the first pipeline should have been called.
	if cleanupCount.Load() < 1 {
		t.Fatalf("expected cleanup called at least once, got %d", cleanupCount.Load())
	}
}

func TestConnManager_BackoffTiming(t *testing.T) {
	mc := &mockConn{}
	mc.alive.Store(true)

	var dialTimes []time.Time
	var dialMu sync.Mutex
	var dialCount atomic.Int32

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, addr, sni string) (transport.Conn, error) {
			n := dialCount.Add(1)
			dialMu.Lock()
			dialTimes = append(dialTimes, time.Now())
			dialMu.Unlock()

			if n == 1 {
				// Initial connect succeeds.
				return mc, nil
			}
			// All reconnect attempts fail.
			return nil, errors.New("server down")
		},
	}

	cm := NewConnManager(ConnManagerConfig{
		Dialer:        dialer,
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   100 * time.Millisecond,
		FreezeTimeout: 10 * time.Second,
		MaxRetries:    4,
	})

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	// Kill connection to trigger reconnect.
	mc.alive.Store(false)

	// Wait for all 4 retry attempts + some margin.
	// Backoff: 0 + 1s + 2s + 4s = 7s total with MaxRetries=4.
	if !waitFor(t, 12*time.Second, func() bool { return dialCount.Load() >= 5 }) {
		t.Logf("dial count = %d (expected 5: 1 initial + 4 retries)", dialCount.Load())
	}

	dialMu.Lock()
	times := make([]time.Time, len(dialTimes))
	copy(times, dialTimes)
	dialMu.Unlock()

	if len(times) < 3 {
		t.Fatalf("not enough dials to verify backoff; got %d", len(times))
	}

	// Verify gaps between reconnect attempts (indices 1→2, 2→3, 3→4).
	// Backoff sequence: Next() returns 0, 1s, 2s, 4s.
	// So gaps between consecutive dials are 1s, 2s, 4s.
	expectedGaps := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	tolerance := 500 * time.Millisecond

	for i := 0; i < len(expectedGaps) && i+2 < len(times); i++ {
		gap := times[i+2].Sub(times[i+1])
		expected := expectedGaps[i]
		if gap < expected-tolerance || gap > expected+tolerance {
			t.Errorf("gap %d: got %v, expected ~%v (±%v)", i, gap, expected, tolerance)
		}
	}
}
