package framing

import "sync"

// SyncFrameWriter wraps a FrameWriter with a mutex to make it safe for
// concurrent use. This is needed when multiple goroutines (e.g. mux writeLoop
// and CoverGenerator) write through the same encoder chain.
type SyncFrameWriter struct {
	mu sync.Mutex
	W  FrameWriter
}

// WriteFrame acquires the mutex and delegates to the underlying FrameWriter.
func (sw *SyncFrameWriter) WriteFrame(f *Frame) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.W.WriteFrame(f)
}
