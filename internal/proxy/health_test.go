package proxy

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"ghost/internal/transport"
)

// blockingReader is an io.ReadCloser whose Read blocks until the context is cancelled.
// Used to simulate the downstream long-poll connection in mock pipelines.
type blockingReader struct {
	ctx context.Context
}

func (r *blockingReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func (r *blockingReader) Close() error { return nil }

// mockConn implements transport.Conn for testing.
type mockConn struct {
	alive     atomic.Bool
	sendFunc  func(ctx context.Context, path string, payload []byte) (io.ReadCloser, error)
	recvFunc  func(ctx context.Context, path string) (io.ReadCloser, error)
	closeFunc func() error
}

func (c *mockConn) Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error) {
	if c.sendFunc != nil {
		return c.sendFunc(ctx, path, payload)
	}
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (c *mockConn) Recv(ctx context.Context, path string) (io.ReadCloser, error) {
	if c.recvFunc != nil {
		return c.recvFunc(ctx, path)
	}
	return &blockingReader{ctx: ctx}, nil
}

func (c *mockConn) Close() error {
	if c.closeFunc != nil {
		return c.closeFunc()
	}
	return nil
}

func (c *mockConn) Alive() bool {
	return c.alive.Load()
}

// mockDialer implements transport.Dialer for testing.
type mockDialer struct {
	dialFunc func(ctx context.Context, addr, sni string) (transport.Conn, error)
}

func (d *mockDialer) Dial(ctx context.Context, addr, sni string) (transport.Conn, error) {
	return d.dialFunc(ctx, addr, sni)
}

// newTestConnManager creates a ConnManager with short intervals for testing.
// The returned mockConn starts alive. The caller can toggle alive as needed.
func newTestConnManager(t *testing.T, healthCheck, freezeTimeout time.Duration) (*ConnManager, *mockConn) {
	t.Helper()
	mc := &mockConn{}
	mc.alive.Store(true)

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, addr, sni string) (transport.Conn, error) {
			return mc, nil
		},
	}

	cm := NewConnManager(ConnManagerConfig{
		Dialer:        dialer,
		ServerAddr:    "127.0.0.1:443",
		ServerSNI:     "example.com",
		HealthCheck:   healthCheck,
		FreezeTimeout: freezeTimeout,
		MaxRetries:    1,
	})
	return cm, mc
}

func TestFreeze_NotTriggeredWhenIdle(t *testing.T) {
	cm, _ := newTestConnManager(t, 100*time.Millisecond, 300*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	// With 0 active streams, freeze detection should never fire.
	time.Sleep(1 * time.Second)

	if !cm.Healthy() {
		t.Fatal("expected healthy: idle pipeline with no active streams should not trigger freeze")
	}
}

func TestHealth_DeadConnection(t *testing.T) {
	var dialCount atomic.Int32

	mc := &mockConn{}
	mc.alive.Store(true)

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, addr, sni string) (transport.Conn, error) {
			dialCount.Add(1)
			// Each dial returns a fresh mock that starts alive.
			// Reuse mc for the first call so we can toggle it.
			if dialCount.Load() == 1 {
				return mc, nil
			}
			fresh := &mockConn{}
			fresh.alive.Store(true)
			return fresh, nil
		},
	}

	cm := NewConnManager(ConnManagerConfig{
		Dialer:        dialer,
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

	if dialCount.Load() != 1 {
		t.Fatalf("expected 1 initial dial, got %d", dialCount.Load())
	}

	// Kill the connection — healthMonitor should detect and trigger reconnect.
	mc.alive.Store(false)

	// Wait for health check to fire + reconnect backoff (1s initial).
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for reconnect dial; dial count = %d", dialCount.Load())
		case <-ticker.C:
			if dialCount.Load() >= 2 {
				return // success: reconnect was triggered
			}
		}
	}
}

func TestHealth_StopsOnCancel(t *testing.T) {
	cm, _ := newTestConnManager(t, 50*time.Millisecond, 300*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Stop should return promptly without hanging.
	done := make(chan struct{})
	go func() {
		cm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return in time — possible goroutine leak")
	}
}

func TestHealth_NoFalsePositiveWithData(t *testing.T) {
	cm, _ := newTestConnManager(t, 100*time.Millisecond, 300*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cm.Stop()

	// Fresh pipeline: ActiveStreams=0, BytesRecv=0.
	// Freeze detection requires ActiveStreams > 0, so it should not fire.
	time.Sleep(1 * time.Second)

	if !cm.Healthy() {
		t.Fatal("expected healthy: no active streams means no false positive freeze")
	}
}
