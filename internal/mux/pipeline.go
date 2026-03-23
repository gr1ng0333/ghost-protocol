package mux

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"ghost/internal/framing"
)

// PipelineConn is the minimal transport connection interface used by the pipeline.
// It is satisfied by transport.Conn without importing the transport package.
type PipelineConn interface {
	Send(ctx context.Context, path string, payload []byte) (io.ReadCloser, error)
	Recv(ctx context.Context, path string) (io.ReadCloser, error)
	Close() error
}

// postWriter adapts PipelineConn.Send into an io.Writer.
// Each Write call sends the data as an HTTP/2 POST request body.
type postWriter struct {
	conn PipelineConn
	path string
	ctx  context.Context
}

func (w *postWriter) Write(p []byte) (int, error) {
	rc, err := w.conn.Send(w.ctx, w.path, p)
	if err != nil {
		return 0, fmt.Errorf("mux.postWriter.Write: %w", err)
	}
	rc.Close()
	return len(p), nil
}

// PipelineWrap provides optional FrameWriter/FrameReader middleware
// for the mux pipeline (e.g., padding/shaping). Both fields are optional;
// nil means no wrapping (frames pass directly to encoder/from decoder).
type PipelineWrap struct {
	// WrapWriter wraps the outbound FrameWriter (encoder).
	// If non-nil, called with the EncoderWriter and should return a new FrameWriter.
	WrapWriter func(framing.FrameWriter) framing.FrameWriter
	// WrapReader wraps the inbound FrameReader (decoder).
	// If non-nil, called with the DecoderReader and should return a new FrameReader.
	WrapReader func(framing.FrameReader) framing.FrameReader
}

// ClientPipeline holds a client mux connected to a transport connection.
type ClientPipeline struct {
	// Mux is the client-side multiplexer for opening streams.
	Mux        ClientMux
	conn       PipelineConn
	downstream io.ReadCloser
}

// NewClientPipeline creates a ClientMux wired to the transport connection.
// uploadPath is the POST endpoint for upstream frames (client → server).
// downloadPath is the GET endpoint for downstream frames (server → client, long-poll).
// wrap provides optional frame middleware (padding/shaping). Pass nil for no wrapping.
//
// The returned ClientPipeline owns the mux. Call Close() to clean up.
func NewClientPipeline(ctx context.Context, conn PipelineConn, uploadPath, downloadPath string, wrap *PipelineWrap) (*ClientPipeline, error) {
	downstream, err := conn.Recv(ctx, downloadPath)
	if err != nil {
		return nil, fmt.Errorf("mux.NewClientPipeline: downstream: %w", err)
	}

	upstream := &postWriter{
		conn: conn,
		path: uploadPath,
		ctx:  ctx,
	}

	// Build FrameWriter chain: mux → [padder →] encoder → transport
	var writer framing.FrameWriter = &framing.EncoderWriter{Enc: framing.NewEncoder(upstream)}
	if wrap != nil && wrap.WrapWriter != nil {
		writer = wrap.WrapWriter(writer)
	}

	// Build FrameReader chain: transport → decoder → [unpadder →] mux
	var reader framing.FrameReader = &framing.DecoderReader{Dec: framing.NewDecoder(downstream)}
	if wrap != nil && wrap.WrapReader != nil {
		reader = wrap.WrapReader(reader)
	}

	mx := NewClientMux(writer, reader)

	return &ClientPipeline{
		Mux:        mx,
		conn:       conn,
		downstream: downstream,
	}, nil
}

// Close shuts down the pipeline: mux, downstream reader, and transport connection.
func (p *ClientPipeline) Close() error {
	p.Mux.Close()
	p.downstream.Close()
	return p.conn.Close()
}

// DerivePaths computes the upload and download API paths from a shared secret.
// Paths rotate daily: "/api/" + hex(HMAC-SHA256(secret, prefix + date)[:8]).
func DerivePaths(sharedSecret [32]byte) (uploadPath, downloadPath string) {
	date := time.Now().UTC().Format("2006-01-02")

	upMAC := hmac.New(sha256.New, sharedSecret[:])
	upMAC.Write([]byte("path-upload-" + date))
	uploadPath = "/api/" + hex.EncodeToString(upMAC.Sum(nil)[:8])

	downMAC := hmac.New(sha256.New, sharedSecret[:])
	downMAC.Write([]byte("path-download-" + date))
	downloadPath = "/api/" + hex.EncodeToString(downMAC.Sum(nil)[:8])

	return uploadPath, downloadPath
}
