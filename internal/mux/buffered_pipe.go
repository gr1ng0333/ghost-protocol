package mux

import (
	"io"
	"sync"
)

// bufferedPipe is a pipe with an internal buffer that decouples writer speed
// from reader speed. Unlike io.Pipe, Write returns immediately if buffer has space.
type bufferedPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte // ring buffer backing store
	r, w   int    // read and write positions in ring buffer
	len    int    // current data length in buffer
	size   int    // buffer capacity
	closed bool
	err    error // error to return on read after close
}

// NewBufferedPipe creates a buffered pipe with the given capacity.
// 2MB is recommended for download path (handles ~100ms of full-speed data at 160 Mbps).
func NewBufferedPipe(size int) *bufferedPipe {
	p := &bufferedPipe{
		buf:  make([]byte, size),
		size: size,
	}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Write appends data to the buffer. Blocks only if buffer is full.
// Returns io.ErrClosedPipe if the pipe has been closed.
func (p *bufferedPipe) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	written := 0
	for len(data) > 0 {
		for p.len == p.size && !p.closed {
			p.cond.Wait()
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}

		// Copy as much as fits into the ring buffer.
		avail := p.size - p.len
		n := len(data)
		if n > avail {
			n = avail
		}

		// Write may wrap around the ring buffer end.
		end := p.w + n
		if end <= p.size {
			copy(p.buf[p.w:end], data[:n])
		} else {
			first := p.size - p.w
			copy(p.buf[p.w:p.size], data[:first])
			copy(p.buf[:end-p.size], data[first:n])
		}
		p.w = (p.w + n) % p.size
		p.len += n
		written += n
		data = data[n:]

		p.cond.Broadcast()
	}
	return written, nil
}

// Read reads from the buffer. Blocks only if buffer is empty.
// Returns io.EOF when pipe is closed and buffer is drained.
func (p *bufferedPipe) Read(buf []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for p.len == 0 {
		if p.closed {
			if p.err != nil {
				return 0, p.err
			}
			return 0, io.EOF
		}
		p.cond.Wait()
	}

	// Read as much as available up to len(buf).
	n := p.len
	if n > len(buf) {
		n = len(buf)
	}

	// Read may wrap around the ring buffer end.
	end := p.r + n
	if end <= p.size {
		copy(buf[:n], p.buf[p.r:end])
	} else {
		first := p.size - p.r
		copy(buf[:first], p.buf[p.r:p.size])
		copy(buf[first:n], p.buf[:end-p.size])
	}
	p.r = (p.r + n) % p.size
	p.len -= n

	p.cond.Broadcast()
	return n, nil
}

// Close closes the write end. Subsequent reads drain the buffer then return io.EOF.
func (p *bufferedPipe) Close() error {
	return p.CloseWithError(nil)
}

// CloseWithError closes the write end with a specific error.
// If err is nil, reads will return io.EOF after the buffer is drained.
func (p *bufferedPipe) CloseWithError(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.err = err
		p.cond.Broadcast()
	}
	return nil
}
