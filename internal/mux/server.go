package mux

import (
	"context"
	"fmt"
	"sync"

	"ghost/internal/framing"
)

// acceptResult pairs a newly opened stream with its target destination.
type acceptResult struct {
	stream *stream
	dest   Destination
}

// serverMux implements ServerMux.
type serverMux struct {
	encoder framing.Encoder
	decoder framing.Decoder

	mu      sync.Mutex
	streams map[uint32]*stream

	acceptCh chan acceptResult // buffered channel for Accept()
	writeCh  chan writeReq     // serialized encoder access (reuses writeReq from client.go)

	done      chan struct{}
	closeOnce sync.Once
}

// NewServerMux creates a server-side multiplexer.
// encoder writes Ghost frames to the outbound connection (downstream to client).
// decoder reads Ghost frames from the inbound connection (upstream from client).
func NewServerMux(encoder framing.Encoder, decoder framing.Decoder) ServerMux {
	m := &serverMux{
		encoder:  encoder,
		decoder:  decoder,
		streams:  make(map[uint32]*stream),
		acceptCh: make(chan acceptResult, 64),
		writeCh:  make(chan writeReq, 256),
		done:     make(chan struct{}),
	}
	go m.writeLoop()
	go m.readLoop()
	return m
}

// Accept waits for and returns the next inbound stream and its destination.
func (m *serverMux) Accept(ctx context.Context) (Stream, Destination, error) {
	select {
	case res, ok := <-m.acceptCh:
		if !ok {
			return nil, Destination{}, fmt.Errorf("mux.ServerMux.Accept: %w", ErrMuxClosed)
		}
		return res.stream, res.dest, nil
	case <-ctx.Done():
		return nil, Destination{}, fmt.Errorf("mux.ServerMux.Accept: %w", ctx.Err())
	case <-m.done:
		return nil, Destination{}, fmt.Errorf("mux.ServerMux.Accept: %w", ErrMuxClosed)
	}
}

// Close shuts down the multiplexer and all active streams.
func (m *serverMux) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)

		m.mu.Lock()
		streams := make(map[uint32]*stream, len(m.streams))
		for id, s := range m.streams {
			streams[id] = s
		}
		m.streams = make(map[uint32]*stream)
		m.mu.Unlock()

		for _, s := range streams {
			s.closeRead()
		}

		close(m.acceptCh)
	})
	return nil
}

// sendFrame serializes a frame send through the writeLoop goroutine.
func (m *serverMux) sendFrame(f *framing.Frame) error {
	errCh := make(chan error, 1)
	select {
	case m.writeCh <- writeReq{frame: f, errCh: errCh}:
		return <-errCh
	case <-m.done:
		return ErrMuxClosed
	}
}

// writeLoop is a goroutine that serializes all encoder.Encode calls.
func (m *serverMux) writeLoop() {
	for {
		select {
		case req := <-m.writeCh:
			req.errCh <- m.encoder.Encode(req.frame)
		case <-m.done:
			return
		}
	}
}

// readLoop is a goroutine that reads frames from the decoder and dispatches
// them to the appropriate stream or the accept channel.
func (m *serverMux) readLoop() {
	defer m.Close()
	for {
		frame, err := m.decoder.Decode()
		if err != nil {
			return
		}

		switch frame.Type {
		case framing.FrameOpen:
			op, err := framing.DecodeOpenPayload(frame.Payload)
			if err != nil {
				continue // skip malformed open
			}

			dest := Destination{Addr: op.Addr, Port: op.Port}
			sid := frame.StreamID

			s := newStream(sid, m.makeWriteFn(sid), m.makeCloseFn(sid))

			m.mu.Lock()
			m.streams[sid] = s
			m.mu.Unlock()

			select {
			case m.acceptCh <- acceptResult{stream: s, dest: dest}:
			case <-m.done:
				return
			}

		case framing.FrameData:
			m.mu.Lock()
			s, ok := m.streams[frame.StreamID]
			m.mu.Unlock()
			if ok {
				s.pushData(frame.Payload)
			}

		case framing.FrameClose:
			m.mu.Lock()
			s, ok := m.streams[frame.StreamID]
			if ok {
				delete(m.streams, frame.StreamID)
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
// back to the client through the serialized write channel.
func (m *serverMux) makeWriteFn(streamID uint32) func([]byte) error {
	return func(data []byte) error {
		return m.sendFrame(&framing.Frame{
			Type:     framing.FrameData,
			StreamID: streamID,
			Payload:  data,
		})
	}
}

// makeCloseFn returns the closeFn callback for a stream. It sends a FrameClose
// and removes the stream from the map.
func (m *serverMux) makeCloseFn(streamID uint32) func() {
	return func() {
		_ = m.sendFrame(&framing.Frame{
			Type:     framing.FrameClose,
			StreamID: streamID,
		})
		m.mu.Lock()
		delete(m.streams, streamID)
		m.mu.Unlock()
	}
}
