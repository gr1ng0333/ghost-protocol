package framing

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Encoder writes frames to an output stream.
type Encoder interface {
	// Encode writes a frame to the underlying writer.
	// The frame is serialized as: [TotalLen:2][Type:1][StreamID:4][PayloadLen:2][Payload][Padding]
	Encode(f *Frame) error
}

// Decoder reads frames from an input stream.
type Decoder interface {
	// Decode reads the next frame from the underlying reader.
	// Returns io.EOF when the stream ends cleanly.
	// Returns io.ErrUnexpectedEOF if the stream ends mid-frame.
	//
	// The Payload and Padding slices in the returned Frame share an
	// underlying buffer allocated per call. Callers that need to retain
	// the data beyond the next Decode call should copy the slices.
	Decode() (*Frame, error)
}

// NewEncoder creates an Encoder writing to w.
func NewEncoder(w io.Writer) Encoder {
	return &encoder{w: w}
}

// NewDecoder creates a Decoder reading from r.
func NewDecoder(r io.Reader) Decoder {
	return &decoder{r: r}
}

type encoder struct {
	w   io.Writer
	hdr [2 + headerSize]byte // reusable buffer for TotalLen + header
}

// Encode writes a frame to the underlying writer.
//
// Wire format: [TotalLen:2][Type:1][StreamID:4][PayloadLen:2][Payload][Padding]
//
// TotalLen is the size of the frame body (everything after the 2-byte prefix):
// headerSize(7) + len(Payload) + len(Padding).
func (e *encoder) Encode(f *Frame) error {
	if err := ValidateFrame(f); err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}

	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("encode frame: payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	totalLen := headerSize + payloadLen + len(f.Padding)
	if totalLen > 65535 {
		return fmt.Errorf("encode frame: total frame body size %d exceeds uint16 max", totalLen)
	}

	// Build the 9-byte header: TotalLen(2) + Type(1) + StreamID(4) + PayloadLen(2)
	binary.BigEndian.PutUint16(e.hdr[0:2], uint16(totalLen))
	e.hdr[2] = byte(f.Type)
	binary.BigEndian.PutUint32(e.hdr[3:7], f.StreamID)
	binary.BigEndian.PutUint16(e.hdr[7:9], uint16(payloadLen))

	if _, err := e.w.Write(e.hdr[:]); err != nil {
		return fmt.Errorf("encode frame: write header: %w", err)
	}

	if payloadLen > 0 {
		if _, err := e.w.Write(f.Payload); err != nil {
			return fmt.Errorf("encode frame: write payload: %w", err)
		}
	}

	if len(f.Padding) > 0 {
		if _, err := e.w.Write(f.Padding); err != nil {
			return fmt.Errorf("encode frame: write padding: %w", err)
		}
	}

	return nil
}

type decoder struct {
	r      io.Reader
	lenBuf [2]byte // reusable buffer for TotalLen
}

// Decode reads the next frame from the underlying reader.
//
// Returns io.EOF on a clean stream end (no bytes read).
// Returns io.ErrUnexpectedEOF if the stream ends mid-frame.
// Returns ErrFrameCorrupt if the frame is structurally invalid.
//
// The Payload and Padding slices in the returned Frame share an underlying
// buffer. Callers that need the data to outlive the next Decode call should
// copy it.
func (d *decoder) Decode() (*Frame, error) {
	// Read 2-byte TotalLen. io.ReadFull returns io.EOF only if zero bytes
	// were read; otherwise it returns io.ErrUnexpectedEOF.
	if _, err := io.ReadFull(d.r, d.lenBuf[:]); err != nil {
		return nil, err
	}

	totalLen := int(binary.BigEndian.Uint16(d.lenBuf[:]))
	if totalLen < headerSize {
		return nil, fmt.Errorf("decode frame: total length %d less than header size %d: %w", totalLen, headerSize, ErrFrameCorrupt)
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, err
	}

	fType := FrameType(buf[0])
	streamID := binary.BigEndian.Uint32(buf[1:5])
	payloadLen := int(binary.BigEndian.Uint16(buf[5:7]))

	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("decode frame: payload length %d exceeds maximum %d: %w", payloadLen, MaxPayloadSize, ErrFrameCorrupt)
	}
	if headerSize+payloadLen > totalLen {
		return nil, fmt.Errorf("decode frame: payload length %d extends beyond frame body of %d: %w", payloadLen, totalLen, ErrFrameCorrupt)
	}

	f := &Frame{
		Type:     fType,
		StreamID: streamID,
		Payload:  buf[headerSize : headerSize+payloadLen],
	}

	paddingLen := totalLen - headerSize - payloadLen
	if paddingLen > 0 {
		f.Padding = buf[headerSize+payloadLen:]
	}

	return f, nil
}
