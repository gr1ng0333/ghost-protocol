package transport

import (
	"sync"
	"testing"
	"time"
)

func TestMetrics_NewMetrics(t *testing.T) {
	before := time.Now()
	m := NewMetrics()
	after := time.Now()

	snap := m.Snapshot()
	if snap.Uptime.Before(before) || snap.Uptime.After(after) {
		t.Errorf("Uptime %v not between %v and %v", snap.Uptime, before, after)
	}
	if snap.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0", snap.ActiveSessions)
	}
	if snap.TotalSessions != 0 {
		t.Errorf("TotalSessions = %d, want 0", snap.TotalSessions)
	}
	if snap.TotalBytesSent != 0 {
		t.Errorf("TotalBytesSent = %d, want 0", snap.TotalBytesSent)
	}
	if snap.TotalBytesRecv != 0 {
		t.Errorf("TotalBytesRecv = %d, want 0", snap.TotalBytesRecv)
	}
	if snap.ReconnectCount != 0 {
		t.Errorf("ReconnectCount = %d, want 0", snap.ReconnectCount)
	}
	if !snap.LastConnect.IsZero() {
		t.Errorf("LastConnect = %v, want zero", snap.LastConnect)
	}
}

func TestMetrics_SessionOpenClose(t *testing.T) {
	m := NewMetrics()

	m.SessionOpened()
	m.SessionOpened()
	m.SessionOpened()
	m.SessionClosed()

	snap := m.Snapshot()
	if snap.ActiveSessions != 2 {
		t.Errorf("ActiveSessions = %d, want 2", snap.ActiveSessions)
	}
	if snap.TotalSessions != 3 {
		t.Errorf("TotalSessions = %d, want 3", snap.TotalSessions)
	}
	if snap.LastConnect.IsZero() {
		t.Error("LastConnect should be set after SessionOpened")
	}
}

func TestMetrics_ByteCounters(t *testing.T) {
	m := NewMetrics()

	m.AddBytesSent(100)
	m.AddBytesSent(200)
	m.AddBytesRecv(50)
	m.AddBytesRecv(75)

	snap := m.Snapshot()
	if snap.TotalBytesSent != 300 {
		t.Errorf("TotalBytesSent = %d, want 300", snap.TotalBytesSent)
	}
	if snap.TotalBytesRecv != 125 {
		t.Errorf("TotalBytesRecv = %d, want 125", snap.TotalBytesRecv)
	}
}

func TestMetrics_Snapshot_ThreadSafe(t *testing.T) {
	m := NewMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			m.SessionOpened()
		}()
		go func() {
			defer wg.Done()
			m.AddBytesSent(10)
		}()
		go func() {
			defer wg.Done()
			m.Snapshot()
		}()
	}
	wg.Wait()

	snap := m.Snapshot()
	if snap.ActiveSessions != 100 {
		t.Errorf("ActiveSessions = %d, want 100", snap.ActiveSessions)
	}
	if snap.TotalSessions != 100 {
		t.Errorf("TotalSessions = %d, want 100", snap.TotalSessions)
	}
	if snap.TotalBytesSent != 1000 {
		t.Errorf("TotalBytesSent = %d, want 1000", snap.TotalBytesSent)
	}

	// Close all 100 sessions concurrently.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.SessionClosed()
		}()
	}
	wg.Wait()

	snap = m.Snapshot()
	if snap.ActiveSessions != 0 {
		t.Errorf("ActiveSessions after close = %d, want 0", snap.ActiveSessions)
	}
	if snap.TotalSessions != 100 {
		t.Errorf("TotalSessions = %d, want 100", snap.TotalSessions)
	}
}

func TestMetrics_Reconnect(t *testing.T) {
	m := NewMetrics()

	m.Reconnect()
	m.Reconnect()
	m.Reconnect()

	snap := m.Snapshot()
	if snap.ReconnectCount != 3 {
		t.Errorf("ReconnectCount = %d, want 3", snap.ReconnectCount)
	}
}

func TestMetrics_SessionClosed_NeverNegative(t *testing.T) {
	m := NewMetrics()

	// Close without any opens — should stay at 0, not go negative.
	m.SessionClosed()
	m.SessionClosed()

	snap := m.Snapshot()
	if snap.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0 (should not go negative)", snap.ActiveSessions)
	}

	// Open one, close two — should stay at 0.
	m.SessionOpened()
	m.SessionClosed()
	m.SessionClosed()

	snap = m.Snapshot()
	if snap.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0 after double close", snap.ActiveSessions)
	}
}
