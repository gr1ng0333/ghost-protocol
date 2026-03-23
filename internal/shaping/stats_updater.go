package shaping

import (
	"context"
	"time"
)

// MuxStatsProvider is satisfied by anything that provides mux-like stats.
// This avoids importing internal/mux from internal/shaping.
type MuxStatsProvider interface {
	ActiveStreamCount() int
	TotalBytesSent() uint64
	TotalBytesRecv() uint64
}

// StatsUpdater periodically reads mux stats and feeds them to
// TimerFrameWriter and CoverGenerator. This resolves the issue where
// TimerFrameWriter.UpdateStats() was never called automatically.
type StatsUpdater struct {
	mux      MuxStatsProvider
	timer    *TimerFrameWriter
	cover    *CoverGenerator
	interval time.Duration
}

// NewStatsUpdater creates a StatsUpdater that polls mux stats at the
// given interval and pushes them to the timer and cover components.
func NewStatsUpdater(mux MuxStatsProvider, timer *TimerFrameWriter, cover *CoverGenerator, interval time.Duration) *StatsUpdater {
	return &StatsUpdater{
		mux:      mux,
		timer:    timer,
		cover:    cover,
		interval: interval,
	}
}

// Run starts the stats polling loop. Blocks until ctx is cancelled.
func (su *StatsUpdater) Run(ctx context.Context) {
	ticker := time.NewTicker(su.interval)
	defer ticker.Stop()

	var lastBytes uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			activeStreams := su.mux.ActiveStreamCount()
			totalBytes := su.mux.TotalBytesSent() + su.mux.TotalBytesRecv()
			byteRate := int64(totalBytes - lastBytes)
			lastBytes = totalBytes

			su.timer.UpdateStats(byteRate, activeStreams)
			su.cover.UpdateStats(byteRate, activeStreams)
		}
	}
}
