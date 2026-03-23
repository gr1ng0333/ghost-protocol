package framing

// FrameWriter is the abstraction for anything that accepts Ghost frames.
// It decouples frame producers (mux) from frame consumers (shaping, transport).
type FrameWriter interface {
	WriteFrame(f *Frame) error
}

// FrameReader is the abstraction for anything that produces Ghost frames.
// Used on the receive path: transport → decoder → unpadder → mux.
type FrameReader interface {
	ReadFrame() (*Frame, error)
}

// EncoderWriter wraps an Encoder as a FrameWriter.
// Each WriteFrame call encodes the frame to the underlying writer.
type EncoderWriter struct {
	Enc Encoder
}

// WriteFrame encodes the frame to the underlying Encoder.
func (ew *EncoderWriter) WriteFrame(f *Frame) error {
	return ew.Enc.Encode(f)
}

// DecoderReader wraps a Decoder as a FrameReader.
// Each ReadFrame call decodes the next frame from the underlying reader.
type DecoderReader struct {
	Dec Decoder
}

// ReadFrame decodes the next frame from the underlying Decoder.
func (dr *DecoderReader) ReadFrame() (*Frame, error) {
	return dr.Dec.Decode()
}
