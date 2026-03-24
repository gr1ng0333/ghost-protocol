package mux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"ghost/internal/framing"
)

// ErrMuxClosed is returned when operating on a closed multiplexer.
var ErrMuxClosed = errors.New("mux closed")

// writeReq is an internal request to serialize a frame through the writeLoop.
type writeReq struct {
	frame *framing.Frame
	errCh chan error
}

// clientMux implements ClientMux.
type clientMux struct {
	writer framing.FrameWriter
	reader framing.FrameReader

	mu      sync.Mutex
	streams map[uint32]*stream
	nextID  uint32 // odd IDs only, starts at 1

	stats MuxStats // protected by mu

	writeCh   chan writeReq
	done      chan struct{}
	closeOnce sync.Once
}

// NewClientMux creates a client-side multiplexer.
// writer sends Ghost frames to the outbound connection (upstream).
// reader reads Ghost frames from the inbound connection (downstream).
func NewClientMux(writer framing.FrameWriter, reader framing.FrameReader) ClientMux {
	m := &clientMux{
		writer:  writer,
		reader:  reader,
		streams: make(map[uint32]*stream),
		nextID:  1,
		writeCh: make(chan writeReq, 256),
		done:    make(chan struct{}),
	}
	go m.writeLoop()
	go m.readLoop()
	return m
}

// Open creates a new stream to the given address and port.
func (m *clientMux) Open(ctx context.Context, addr string, port uint16) (Stream, error) {
	select {
	case <-m.done:
		return nil, fmt.Errorf("mux.ClientMux.Open: %w", ErrMuxClosed)
	case <-ctx.Done():
		return nil, fmt.Errorf("mux.ClientMux.Open: %w", ctx.Err())
	default:
	}

	m.mu.Lock()
	streamID := m.nextID
	m.nextID += 2
	m.mu.Unlock()

	// Detect address type.
	addrType := framing.AddrDomain
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			addrType = framing.AddrIPv4
		} else {
			addrType = framing.AddrIPv6
		}
	}

	payload, err := framing.EncodeOpenPayload(&framing.OpenPayload{
		Proto:    framing.ProtoTCP,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	})
	if err != nil {
		return nil, fmt.Errorf("mux.ClientMux.Open: encode open payload: %w", err)
	}

	if err := m.sendFrame(&framing.Frame{
		Type:     framing.FrameOpen,
		StreamID: streamID,
		Payload:  payload,
	}); err != nil {
		return nil, fmt.Errorf("mux.ClientMux.Open: %w", err)
	}

	s := newStream(streamID, m.makeWriteFn(streamID), m.makeCloseFn(streamID), m.makeCloseWriteFn(streamID))

	m.mu.Lock()
	m.streams[streamID] = s
	m.stats.TotalOpened++
	m.stats.ActiveStreams++
	m.mu.Unlock()

	return s, nil
}

// Close shuts down the multiplexer and all active streams.
func (m *clientMux) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)

		m.mu.Lock()
		streams := make(map[uint32]*stream, len(m.streams))
		for id, s := range m.streams {
			streams[id] = s
		}
		m.streams = make(map[uint32]*stream)
		m.stats.ActiveStreams = 0
		m.mu.Unlock()

		for _, s := range streams {
			s.closeRead()
		}
	})
	return nil
}

// Stats returns a snapshot of the multiplexer runtime statistics.
func (m *clientMux) Stats() MuxStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// sendFrame serializes a frame send through the writeLoop goroutine.
func (m *clientMux) sendFrame(f *framing.Frame) error {
	errCh := make(chan error, 1)
	select {
	case m.writeCh <- writeReq{frame: f, errCh: errCh}:
		return <-errCh
	case <-m.done:
		return ErrMuxClosed
	}
}

// writeLoop is a goroutine that serializes all encoder.Encode calls.
func (m *clientMux) writeLoop() {
	for {
		select {
		case req := <-m.writeCh:
			req.errCh <- m.writer.WriteFrame(req.frame)
		case <-m.done:
			return
		}
	}
}

// readLoop is a goroutine that reads frames from the decoder and dispatches
// them to the appropriate stream.
func (m *clientMux) readLoop() {
	defer m.Close()
	for {
		frame, err := m.reader.ReadFrame()
		if err != nil {
			return
		}
		switch frame.Type {
		case framing.FrameData:
			m.mu.Lock()
			s, ok := m.streams[frame.StreamID]
			m.mu.Unlock()
			if ok {
				s.pushData(frame.Payload)
				m.mu.Lock()
				m.stats.BytesRecv += uint64(len(frame.Payload))
				m.mu.Unlock()
			}
		case framing.FrameClose:
			m.mu.Lock()
			s, ok := m.streams[frame.StreamID]
			if ok {
				delete(m.streams, frame.StreamID)
				m.stats.ActiveStreams--
				m.stats.TotalClosed++
			}
			m.mu.Unlock()
			if ok {
				s.closeRead()
			}
		case framing.FramePadding, framing.FrameKeepAlive:
			// Silently discard.
		}
	}
}

// makeWriteFn returns the writeFn callback for a stream. It sends a FrameData
// through the serialized write channel and tracks bytes sent.
func (m *clientMux) makeWriteFn(streamID uint32) func([]byte) error {
	return func(data []byte) error {
		err := m.sendFrame(&framing.Frame{
			Type:     framing.FrameData,
			StreamID: streamID,
			Payload:  data,
		})
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.stats.BytesSent += uint64(len(data))
		m.mu.Unlock()
		return nil
	}
}

// makeCloseFn returns the closeFn callback for a stream. It sends a FrameClose
// and removes the stream from the map.
func (m *clientMux) makeCloseFn(streamID uint32) func() {
	return func() {
		// Best-effort send of FrameClose; ignore errors if mux is already closed.
		_ = m.sendFrame(&framing.Frame{
			Type:     framing.FrameClose,
			StreamID: streamID,
		})
		m.mu.Lock()
		if _, ok := m.streams[streamID]; ok {
			delete(m.streams, streamID)
			m.stats.ActiveStreams--
			m.stats.TotalClosed++
		}
		m.mu.Unlock()
	}
}

// makeCloseWriteFn returns a callback that sends a FrameClose for
// half-close semantics without removing the stream from the map.
func (m *clientMux) makeCloseWriteFn(streamID uint32) func() error {
	return func() error {
		return m.sendFrame(&framing.Frame{
			Type:     framing.FrameClose,
			StreamID: streamID,
		})
	}
}
