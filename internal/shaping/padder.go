package shaping

import "ghost/internal/framing"

// Padder adjusts frame sizes to match a target traffic profile.
type Padder interface {
	// Pad takes a frame and returns one or more frames with padding applied.
	Pad(f *framing.Frame) []*framing.Frame
	// Unpad strips padding from a frame. Returns nil if the frame is pure padding.
	Unpad(f *framing.Frame) *framing.Frame
}
