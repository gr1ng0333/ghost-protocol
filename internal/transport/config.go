package transport

// H2Config holds HTTP/2 SETTINGS and behavioral parameters
// that must match Chrome's fingerprint.
type H2Config struct {
	HeaderTableSize   uint32   // Chrome 146: 65536
	EnablePush        uint32   // Chrome 146: 0
	InitialWindowSize uint32   // Chrome 146: 6291456
	MaxHeaderListSize uint32   // Chrome 146: 262144
	WindowUpdateSize  uint32   // Chrome 146: 15663105
	PseudoHeaderOrder []string // Chrome 146: [":method", ":authority", ":scheme", ":path"]
	PriorityMode      string   // "none" = no priority frames (Chrome behavior)
	ALPSEnabled       bool     // informational — ALPS handled by uTLS preset
}

// DefaultChromeH2Config returns H2Config matching Chrome 146.
func DefaultChromeH2Config() H2Config {
	return H2Config{
		HeaderTableSize:   65536,
		EnablePush:        0,
		InitialWindowSize: 6291456,
		MaxHeaderListSize: 262144,
		WindowUpdateSize:  15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		PriorityMode:      "none",
		ALPSEnabled:       true,
	}
}
