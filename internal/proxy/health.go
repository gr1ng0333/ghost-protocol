package proxy

import (
	"log/slog"
	"time"
)

// healthMonitor periodically checks connection health and detects
// data freezes. It runs as a goroutine for the lifetime of the ConnManager.
//
// Detection strategies:
//  1. Full freeze: both BytesSent and BytesRecv are unchanged while active
//     streams exist. Triggers after FreezeTimeout.
//  2. Download stall: BytesRecv is unchanged but BytesSent keeps advancing
//     (writes go to a local buffer, masking a dead server→client path).
//     Triggers after 2×FreezeTimeout.
//  3. Transport dead: the HTTP/2 connection's CanTakeNewRequest() returns false
//     (e.g. after TCP keepalive detects a dead socket). Triggers immediately.
func (cm *ConnManager) healthMonitor() {
	defer cm.wg.Done()
	ticker := time.NewTicker(cm.cfg.HealthCheck)
	defer ticker.Stop()

	var lastBytesRecv uint64
	var lastBytesSent uint64
	lastActivity := time.Now()
	lastRecvChange := time.Now()

	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-cm.healthResetCh:
			lastBytesRecv = 0
			lastBytesSent = 0
			lastActivity = time.Now()
			lastRecvChange = time.Now()
		case <-ticker.C:
			cm.mu.RLock()
			p := cm.pipeline
			c := cm.conn
			cm.mu.RUnlock()

			if p == nil {
				continue
			}

			stats := p.Mux.Stats()

			// Track when download bytes last changed.
			if stats.BytesRecv != lastBytesRecv {
				lastRecvChange = time.Now()
			}

			if stats.ActiveStreams > 0 {
				// Full freeze: both directions stalled.
				if stats.BytesSent == lastBytesSent && stats.BytesRecv == lastBytesRecv {
					if time.Since(lastActivity) > cm.cfg.FreezeTimeout {
						slog.Warn("connmgr: data freeze detected",
							"idle_duration", time.Since(lastActivity),
							"active_streams", stats.ActiveStreams,
							"bytes_sent", stats.BytesSent,
							"bytes_recv", stats.BytesRecv,
						)
						cm.triggerReconnect()
						lastActivity = time.Now()
						lastRecvChange = time.Now()
					}
				} else {
					lastActivity = time.Now()
				}

				// Download stall: upload buffer accepting data but server
				// hasn't sent anything. The 2MB buffered pipe lets BytesSent
				// increase even when the HTTP/2 connection is dead.
				if stats.BytesRecv == lastBytesRecv && stats.BytesSent != lastBytesSent {
					if time.Since(lastRecvChange) > 2*cm.cfg.FreezeTimeout {
						slog.Warn("connmgr: download stall detected",
							"recv_stall", time.Since(lastRecvChange),
							"active_streams", stats.ActiveStreams,
							"bytes_sent", stats.BytesSent,
							"bytes_recv", stats.BytesRecv,
						)
						cm.triggerReconnect()
						lastActivity = time.Now()
						lastRecvChange = time.Now()
					}
				}
			} else {
				lastActivity = time.Now()
			}

			lastBytesRecv = stats.BytesRecv
			lastBytesSent = stats.BytesSent

			// Connection liveness check
			if c != nil && !c.Alive() {
				slog.Warn("connmgr: connection dead")
				cm.triggerReconnect()
			}
		}
	}
}
