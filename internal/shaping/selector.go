package shaping

// Selector chooses the shaping mode based on traffic characteristics.
type Selector interface {
	// Select returns the appropriate Mode for the given byte rate and stream count.
	Select(byteRate int64, streamCount int) Mode
}
