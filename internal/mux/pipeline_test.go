package mux

import (
	"bytes"
	"context"
	"io"
	"testing"

	"ghost/internal/framing"
)

// mockPipelineConn implements PipelineConn for testing.
type mockPipelineConn struct {
	sendBuf  bytes.Buffer // captures data sent via Send
	recvData []byte       // data to return from Recv
	closed   bool
}

func (m *mockPipelineConn) Send(_ context.Context, _ string, payload []byte) (io.ReadCloser, error) {
	m.sendBuf.Write(payload)
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (m *mockPipelineConn) Recv(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.recvData)), nil
}

func (m *mockPipelineConn) Close() error {
	m.closed = true
	return nil
}

// mockStreamConn extends mockPipelineConn with SendStream support.
type mockStreamConn struct {
	mockPipelineConn
	streamBody io.Reader // set after SendStream is called
}

func (m *mockStreamConn) SendStream(_ context.Context, _ string, body io.Reader) (io.ReadCloser, error) {
	m.streamBody = body
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func TestDerivePaths(t *testing.T) {
	t.Parallel()

	secret := [32]byte{1, 2, 3, 4, 5}
	up, down := DerivePaths(secret)

	// Paths should start with /api/ and be hex-encoded.
	if len(up) < 6 || up[:5] != "/api/" {
		t.Fatalf("upload path format invalid: %q", up)
	}
	if len(down) < 6 || down[:5] != "/api/" {
		t.Fatalf("download path format invalid: %q", down)
	}

	// Upload and download paths must be different.
	if up == down {
		t.Fatal("upload and download paths must differ")
	}

	// Same secret → same paths (deterministic within same day).
	up2, down2 := DerivePaths(secret)
	if up != up2 || down != down2 {
		t.Fatal("DerivePaths not deterministic for same secret")
	}

	// Different secret → different paths.
	secret2 := [32]byte{9, 8, 7, 6, 5}
	up3, down3 := DerivePaths(secret2)
	if up == up3 || down == down3 {
		t.Fatal("different secrets should produce different paths")
	}
}

func TestDeriveStreamUploadPath(t *testing.T) {
	t.Parallel()

	path := DeriveStreamUploadPath("/api/abcd1234")

	if len(path) < 6 || path[:5] != "/api/" {
		t.Fatalf("stream upload path format invalid: %q", path)
	}

	// Deterministic.
	if path != DeriveStreamUploadPath("/api/abcd1234") {
		t.Fatal("DeriveStreamUploadPath not deterministic")
	}

	// Different input → different output.
	path2 := DeriveStreamUploadPath("/api/other5678")
	if path == path2 {
		t.Fatal("different inputs should produce different stream paths")
	}
}

func TestPostWriterWrite(t *testing.T) {
	t.Parallel()

	conn := &mockPipelineConn{}
	pw := &postWriter{
		conn: conn,
		path: "/api/upload",
		ctx:  context.Background(),
	}

	data := []byte("hello mux pipeline")
	n, err := pw.Write(data)
	if err != nil {
		t.Fatalf("postWriter.Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("wrote %d, want %d", n, len(data))
	}
	if !bytes.Equal(conn.sendBuf.Bytes(), data) {
		t.Fatalf("send buffer mismatch: got %q, want %q", conn.sendBuf.String(), string(data))
	}
}

func TestNewClientPipeline_PostMode(t *testing.T) {
	t.Parallel()

	conn := &mockPipelineConn{
		recvData: []byte{}, // empty downstream
	}

	ctx := context.Background()
	pipeline, err := NewClientPipeline(ctx, conn, "/api/up", "/api/down", nil)
	if err != nil {
		t.Fatalf("NewClientPipeline: %v", err)
	}

	// Pipeline should have a valid Mux.
	if pipeline.Mux == nil {
		t.Fatal("Mux is nil")
	}

	// Close should clean up.
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !conn.closed {
		t.Fatal("transport connection not closed")
	}
}

func TestNewClientPipeline_WithWrap(t *testing.T) {
	t.Parallel()

	conn := &mockPipelineConn{
		recvData: []byte{},
	}

	writerCalled := false
	readerCalled := false
	wrap := &PipelineWrap{
		WrapWriter: func(fw framing.FrameWriter) framing.FrameWriter {
			writerCalled = true
			return fw
		},
		WrapReader: func(fr framing.FrameReader) framing.FrameReader {
			readerCalled = true
			return fr
		},
	}

	ctx := context.Background()
	pipeline, err := NewClientPipeline(ctx, conn, "/api/up", "/api/down", wrap)
	if err != nil {
		t.Fatalf("NewClientPipeline with wrap: %v", err)
	}
	defer pipeline.Close()

	if !writerCalled {
		t.Error("WrapWriter was not called")
	}
	if !readerCalled {
		t.Error("WrapReader was not called")
	}
}

func TestNewClientPipeline_StreamMode(t *testing.T) {
	t.Parallel()

	conn := &mockStreamConn{
		mockPipelineConn: mockPipelineConn{
			recvData: []byte{},
		},
	}

	ctx := context.Background()
	pipeline, err := NewClientPipeline(ctx, conn, "/api/up", "/api/down", nil)
	if err != nil {
		t.Fatalf("NewClientPipeline stream mode: %v", err)
	}

	// streamPW should be set for streaming upload.
	if pipeline.streamPW == nil {
		t.Error("streamPW should be set for streamConn")
	}

	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
