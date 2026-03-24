package transport

import (
	"sync"
	"time"
)

// Metrics collects server runtime statistics.
// All methods are safe for concurrent use.
type Metrics struct {
	mu             sync.RWMutex
	activeSessions int
	totalSessions  uint64
	totalBytesSent uint64
	totalBytesRecv uint64
	uptime         time.Time
	lastConnect    time.Time
	reconnectCount uint64
}

// NewMetrics creates a Metrics instance with uptime set to now.
func NewMetrics() *Metrics {
	return &Metrics{
		uptime: time.Now(),
	}
}

// MetricsSnapshot is a point-in-time copy of runtime statistics.
type MetricsSnapshot struct {
	ActiveSessions int       `json:"active_sessions"`
	TotalSessions  uint64    `json:"total_sessions"`
	TotalBytesSent uint64    `json:"bytes_sent"`
	TotalBytesRecv uint64    `json:"bytes_recv"`
	Uptime         time.Time `json:"uptime"`
	LastConnect    time.Time `json:"last_connect"`
	ReconnectCount uint64    `json:"reconnect_count"`
}

// Snapshot returns a thread-safe copy of current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return MetricsSnapshot{
		ActiveSessions: m.activeSessions,
		TotalSessions:  m.totalSessions,
		TotalBytesSent: m.totalBytesSent,
		TotalBytesRecv: m.totalBytesRecv,
		Uptime:         m.uptime,
		LastConnect:    m.lastConnect,
		ReconnectCount: m.reconnectCount,
	}
}

// SessionOpened increments active and total session counters,
// and updates LastConnect.
func (m *Metrics) SessionOpened() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeSessions++
	m.totalSessions++
	m.lastConnect = time.Now()
}

// SessionClosed decrements active session counter.
// Guards against going negative from duplicate or spurious close calls.
func (m *Metrics) SessionClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeSessions > 0 {
		m.activeSessions--
	}
}

// AddBytesSent adds n to total bytes sent counter.
func (m *Metrics) AddBytesSent(n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalBytesSent += n
}

// AddBytesRecv adds n to total bytes received counter.
func (m *Metrics) AddBytesRecv(n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalBytesRecv += n
}

// Reconnect increments the reconnect counter.
func (m *Metrics) Reconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconnectCount++
}
