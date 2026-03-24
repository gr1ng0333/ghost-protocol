package mux

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"ghost/internal/framing"
)

// ErrStreamClosed is returned when performing I/O on a closed stream.
var ErrStreamClosed = errors.New("stream closed")

// stream implements Stream for a single multiplexed tunnel stream.
type stream struct {
	id           uint32
	readBuf      chan []byte        // incoming data chunks queued by mux readLoop
	readLeft     []byte             // leftover from previous Read that wasn't fully consumed
	writeFn      func([]byte) error // callback: sends FrameData through mux outbound channel
	closeFn      func()             // callback: sends FrameClose and cleans up (full close)
	closeWriteFn func() error       // callback: sends FrameClose without map cleanup (half-close)

	closed         atomic.Bool
	closeOnce      sync.Once
	writeClosed    atomic.Bool
	writeCloseOnce sync.Once
	readClosed     atomic.Bool
	readCloseOnce  sync.Once
}

// newStream creates a new stream with the given ID and mux callbacks.
// closeWriteFn may be nil; if nil, CloseWrite falls back to full Close.
func newStream(id uint32, writeFn func([]byte) error, closeFn func(), closeWriteFn func() error) *stream {
	return &stream{
		id:           id,
		readBuf:      make(chan []byte, 256),
		writeFn:      writeFn,
		closeFn:      closeFn,
		closeWriteFn: closeWriteFn,
	}
}

// ID returns the unique stream identifier.
func (s *stream) ID() uint32 {
	return s.id
}

// Read reads data from the stream. It blocks until data is available,
// the stream is closed locally, or the remote side closes the stream.
func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Drain leftover bytes from a previous read first.
	if len(s.readLeft) > 0 {
		n := copy(p, s.readLeft)
		s.readLeft = s.readLeft[n:]
		if len(s.readLeft) == 0 {
			s.readLeft = nil
		}
		return n, nil
	}

	// Block for the next chunk from the mux readLoop.
	chunk, ok := <-s.readBuf
	if !ok {
		// Channel closed — remote side closed the stream.
		return 0, io.EOF
	}

	n := copy(p, chunk)
	if n < len(chunk) {
		s.readLeft = chunk[n:]
	}
	return n, nil
}

// CloseWrite signals the end of the write direction for this stream.
// The remote side will receive EOF on reads for this stream, but
// the local side can still read data from the remote.
// After CloseWrite, further Write calls return ErrStreamClosed.
// It is safe to call multiple times.
func (s *stream) CloseWrite() error {
	var err error
	s.writeCloseOnce.Do(func() {
		s.writeClosed.Store(true)
		if s.closeWriteFn != nil {
			err = s.closeWriteFn()
		}
	})
	return err
}

// Write writes data to the stream, splitting into chunks of MaxPayloadSize
// if necessary.
func (s *stream) Write(p []byte) (int, error) {
	if s.writeClosed.Load() || s.closed.Load() {
		return 0, ErrStreamClosed
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > framing.MaxPayloadSize {
			chunk = p[:framing.MaxPayloadSize]
		}
		if err := s.writeFn(chunk); err != nil {
			return total, fmt.Errorf("mux.stream.Write: %w", err)
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close closes the stream in both directions. It is safe to call multiple times.
func (s *stream) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		// Mark write direction closed (idempotent via writeCloseOnce).
		s.writeCloseOnce.Do(func() {
			s.writeClosed.Store(true)
		})
		s.closeFn()
		// Close the read channel so blocked Reads return EOF.
		s.readCloseOnce.Do(func() {
			s.readClosed.Store(true)
			close(s.readBuf)
		})
	})
	return nil
}

// pushData is called by the mux readLoop to deliver incoming data.
// It queues data into readBuf. If the stream is closed, data is silently dropped.
func (s *stream) pushData(data []byte) {
	if s.closed.Load() || s.readClosed.Load() {
		return
	}
	// Copy data since the decoder may reuse its buffer.
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case s.readBuf <- cp:
	default:
		// Buffer full — accept backpressure with a blocking send.
		s.readBuf <- cp
	}
}

// closeRead is called by the mux when a remote FrameClose is received.
// It closes the readBuf channel so Read returns io.EOF.
// The write direction is unaffected, allowing half-close semantics.
func (s *stream) closeRead() {
	s.readCloseOnce.Do(func() {
		s.readClosed.Store(true)
		close(s.readBuf)
	})
}
