package framing

import (
	"bytes"
	"testing"
)

// FuzzDecoder feeds arbitrary bytes into the frame Decoder.
// Any panic is a crash/DoS vulnerability — errors are expected and fine.
func FuzzDecoder(f *testing.F) {
	// Seed 1: FrameData, StreamID=1, Payload="Hi"
	f.Add([]byte{
		0x00, 0x09, // TotalLen = 9
		0x00,                   // Type = FrameData
		0x00, 0x00, 0x00, 0x01, // StreamID = 1
		0x00, 0x02, // PayloadLen = 2
		0x48, 0x69, // "Hi"
	})

	// Seed 2: FrameOpen, StreamID=3, TCP/IPv4 1.2.3.4:80
	f.Add([]byte{
		0x00, 0x0F, // TotalLen = 15
		0x01,                   // Type = FrameOpen
		0x00, 0x00, 0x00, 0x03, // StreamID = 3
		0x00, 0x08, // PayloadLen = 8
		0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	})

	// Seed 3: FrameClose, StreamID=7 (header only, no payload)
	f.Add([]byte{
		0x00, 0x07, // TotalLen = 7
		0x02,                   // Type = FrameClose
		0x00, 0x00, 0x00, 0x07, // StreamID = 7
		0x00, 0x00, // PayloadLen = 0
	})

	// Seed 4: FrameKeepAlive, StreamID=0
	f.Add([]byte{
		0x00, 0x07, // TotalLen = 7
		0x04,                   // Type = FrameKeepAlive
		0x00, 0x00, 0x00, 0x00, // StreamID = 0
		0x00, 0x00, // PayloadLen = 0
	})

	// Seed 5: two frames concatenated
	f.Add([]byte{
		0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x48, 0x69,
		0x00, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewDecoder(bytes.NewReader(data))
		for {
			_, err := dec.Decode()
			if err != nil {
				return
			}
		}
	})
}

// FuzzDecodeOpenPayload feeds arbitrary bytes into DecodeOpenPayload.
// Any panic is a crash/DoS vulnerability.
func FuzzDecodeOpenPayload(f *testing.F) {
	// Seed 1: valid IPv4 TCP open — 1.2.3.4:80
	f.Add([]byte{0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50})

	// Seed 2: valid IPv4 UDP open — 127.0.0.1:80
	f.Add([]byte{0x03, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50})

	// Seed 3: valid domain TCP open — "example.com":80
	f.Add([]byte{0x01, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50})

	// Seed 4: empty
	f.Add([]byte{})

	// Seed 5: single byte
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		DecodeOpenPayload(data) //nolint:errcheck // errors are fine, panics are not
	})
}
