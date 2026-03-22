package mux

import (
	"context"
	"io"
)

// Stream represents a single multiplexed tunnel stream.
type Stream interface {
	io.ReadWriteCloser
	// ID returns the unique stream identifier.
	ID() uint32
}

// ClientMux manages outbound multiplexed streams.
type ClientMux interface {
	// Open creates a new stream to the given address and port.
	Open(ctx context.Context, addr string, port uint16) (Stream, error)
	// Close shuts down the multiplexer and all active streams.
	Close() error
	// Stats returns runtime statistics for the multiplexer.
	Stats() MuxStats
}

// ServerMux manages inbound multiplexed streams.
type ServerMux interface {
	// Accept waits for and returns the next inbound stream and its destination.
	Accept(ctx context.Context) (Stream, Destination, error)
	// Close shuts down the multiplexer and all active streams.
	Close() error
}

// Destination describes where a stream should be connected.
type Destination struct {
	Addr string
	Port uint16
}

// MuxStats holds multiplexer runtime statistics.
type MuxStats struct {
	ActiveStreams int
	TotalOpened   uint64
	TotalClosed   uint64
	BytesSent     uint64
	BytesRecv     uint64
}
