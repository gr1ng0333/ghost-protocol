package framing

import "fmt"

// ValidateFrame checks that f satisfies Ghost's structural invariants.
//
// It enforces only the invariants that are clearly required by the wire format
// and documented frame semantics. It does not apply semantic rules beyond what
// is explicitly specified in the architecture.
//
// Rules applied:
//   - f must not be nil.
//   - f.Type must be one of the six documented FrameType constants (0x00–0x05).
//   - len(f.Payload) must not exceed MaxPayloadSize.
//   - FrameData, FrameOpen, and FrameClose must carry a non-zero StreamID,
//     because those frame types address a specific tunnel stream.
//   - FrameOpen must carry a non-empty Payload (the serialised OpenPayload).
func ValidateFrame(f *Frame) error {
	if f == nil {
		return fmt.Errorf("validate frame: nil frame")
	}

	switch f.Type {
	case FrameData, FrameOpen, FrameClose, FramePadding, FrameKeepAlive, FrameUDP:
		// known, valid type
	default:
		return fmt.Errorf("validate frame: unknown type 0x%02x: %w", f.Type, ErrFrameCorrupt)
	}

	if len(f.Payload) > MaxPayloadSize {
		return fmt.Errorf("validate frame: payload size %d exceeds maximum %d: %w",
			len(f.Payload), MaxPayloadSize, ErrFrameCorrupt)
	}

	// FrameData, FrameOpen, and FrameClose address a specific stream and
	// therefore require a non-zero StreamID. StreamID 0 is never a valid
	// user-stream identifier.
	switch f.Type {
	case FrameData, FrameOpen, FrameClose:
		if f.StreamID == 0 {
			return fmt.Errorf("validate frame: type 0x%02x requires non-zero StreamID: %w",
				f.Type, ErrFrameCorrupt)
		}
	}

	// FrameOpen must carry a serialised OpenPayload; an empty payload cannot
	// be decoded into a valid destination address.
	if f.Type == FrameOpen && len(f.Payload) == 0 {
		return fmt.Errorf("validate frame: FrameOpen requires non-empty payload: %w", ErrFrameCorrupt)
	}

	return nil
}
