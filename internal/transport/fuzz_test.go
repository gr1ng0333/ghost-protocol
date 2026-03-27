package transport

import (
	"testing"
)

// FuzzParseClientHello feeds arbitrary bytes into parseClientHello.
// Any panic is a crash/DoS vulnerability — errors are expected and fine.
func FuzzParseClientHello(f *testing.F) {
	// Seed 1: minimal valid ClientHello (no extensions) from test helper
	f.Add(buildMinimalClientHello())

	// Seed 2: ClientHello with ALPN extension
	f.Add(buildMinimalClientHelloWithALPN([]string{"h2", "http/1.1"}))

	// Seed 3: too short to be valid
	f.Add([]byte{0x16, 0x03, 0x01})

	// Seed 4: wrong content type
	f.Add([]byte{
		0x17, 0x03, 0x01, 0x00, 0x26,
		0x01, 0x00, 0x00, 0x22,
		0x03, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // SessionID len = 0
		0x00, 0x02, // CipherSuites len
		0x00, 0x2f, // one suite
		0x01, 0x00, // compression
	})

	// Seed 5: empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		parseClientHello(data) //nolint:errcheck // errors are fine, panics are not
	})
}
