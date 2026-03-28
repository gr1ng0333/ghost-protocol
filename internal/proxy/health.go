package proxy

import (
	"log/slog"
	"time"
)

// healthMonitor periodically checks connection health and detects
// data freezes. It runs as a goroutine for the lifetime of the ConnManager.
//
// Detection strategies:
//  1. Transport dead: the HTTP/2 connection's CanTakeNewRequest() returns false
//     (e.g. after PING timeout or TCP keepalive detects a dead socket).
//     Triggers immediately.
//  2. Full freeze: both BytesSent and BytesRecv are unchanged while active
//     streams exist AND the transport is dead. Mux-level stats don't include
//     cover traffic, so an idle user session with healthy cover traffic would
//     appear frozen — the transport liveness check prevents false positives.
//  3. Download stall: BytesRecv is unchanged but BytesSent keeps advancing
//     AND the transport is dead. Same false-positive guard applies.
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

			// Connection liveness check — most reliable signal.
			// HTTP/2 PING keepalive (ReadIdleTimeout) detects dead
			// connections at the transport layer. When the connection
			// dies, CanTakeNewRequest() returns false.
			if c != nil && !c.Alive() {
				slog.Warn("connmgr: connection dead")
				cm.triggerReconnect()
				continue
			}

			stats := p.Mux.Stats()

			// Track when download bytes last changed.
			if stats.BytesRecv != lastBytesRecv {
				lastRecvChange = time.Now()
			}

			if stats.ActiveStreams > 0 {
				// Full freeze: both directions stalled AND transport is dead.
				// Cover traffic (padding/keepalive) bypasses mux stats, so
				// idle user sessions look frozen even when the connection is
				// healthy. Guard with Alive() to avoid false reconnects.
				if stats.BytesSent == lastBytesSent && stats.BytesRecv == lastBytesRecv {
					if time.Since(lastActivity) > cm.cfg.FreezeTimeout {
						if c == nil || !c.Alive() {
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
					}
				} else {
					lastActivity = time.Now()
				}

				// Download stall: upload buffer accepting data but server
				// hasn't sent anything. Guard with Alive() — buffered pipe
				// accepts writes even when the HTTP/2 connection is healthy
				// but there's simply no server→client data.
				if stats.BytesRecv == lastBytesRecv && stats.BytesSent != lastBytesSent {
					if time.Since(lastRecvChange) > 2*cm.cfg.FreezeTimeout {
						if c == nil || !c.Alive() {
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
				}
			} else {
				lastActivity = time.Now()
			}

			lastBytesRecv = stats.BytesRecv
			lastBytesSent = stats.BytesSent
		}
	}
}
