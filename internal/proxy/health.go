package proxy

import (
	"log/slog"
	"time"
)

// healthMonitor periodically checks connection health and detects
// TSPU data freezes. It runs as a goroutine for the lifetime of
// the ConnManager.
func (cm *ConnManager) healthMonitor() {
	defer cm.wg.Done()
	ticker := time.NewTicker(cm.cfg.HealthCheck)
	defer ticker.Stop()

	var lastBytesRecv uint64
	lastActivity := time.Now()

	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-ticker.C:
			cm.mu.RLock()
			p := cm.pipeline
			c := cm.conn
			cm.mu.RUnlock()

			if p == nil {
				continue
			}

			stats := p.Mux.Stats()

			// Freeze detection: if there are active streams but BytesRecv
			// hasn't changed, data should be flowing but isn't. TSPU freezes
			// connections after ~16KB on suspicious IPs — connection goes silent.
			if stats.ActiveStreams > 0 && stats.BytesRecv == lastBytesRecv {
				if time.Since(lastActivity) > cm.cfg.FreezeTimeout {
					slog.Warn("connmgr: data freeze detected",
						"idle_duration", time.Since(lastActivity),
						"active_streams", stats.ActiveStreams,
						"bytes_recv", stats.BytesRecv,
					)
					cm.triggerReconnect()
					lastActivity = time.Now() // prevent rapid re-trigger
				}
			} else {
				lastActivity = time.Now()
			}
			lastBytesRecv = stats.BytesRecv

			// Connection liveness check
			if c != nil && !c.Alive() {
				slog.Warn("connmgr: connection dead")
				cm.triggerReconnect()
			}
		}
	}
}
