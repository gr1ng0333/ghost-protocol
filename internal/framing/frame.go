package framing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// ErrFrameCorrupt indicates a malformed or invalid frame.
var ErrFrameCorrupt = errors.New("frame corrupted")

// FrameType identifies the kind of frame.
type FrameType uint8

const (
	FrameData      FrameType = 0x00 // Tunnel data payload (TCP stream)
	FrameOpen      FrameType = 0x01 // Open a new stream
	FrameClose     FrameType = 0x02 // Close a stream
	FramePadding   FrameType = 0x03 // Padding-only frame (discarded by receiver)
	FrameKeepAlive FrameType = 0x04 // Connection keepalive
	FrameUDP       FrameType = 0x05 // UDP datagram (for DNS, QUIC passthrough)
)

// MaxPayloadSize is the maximum payload size per Ghost frame.
// Constrained by HTTP/2 default max frame size (16384) minus Ghost overhead
// (2 TotalLen + 1 Type + 4 StreamID + 2 PayloadLen = 9 bytes). We use 16000
// to leave room for padding within a single HTTP/2 DATA frame.
const MaxPayloadSize = 16000

// headerSize is the fixed-size portion of the frame body after TotalLen:
// Type(1) + StreamID(4) + PayloadLen(2) = 7 bytes
const headerSize = 7

// Frame is the fundamental unit of Ghost wire protocol.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte // For FrameData: tunnel data. For FrameOpen: encoded OpenPayload. For others: may be empty.
	Padding  []byte // Padding bytes appended after payload. Set by traffic shaping (Phase 3). May be nil.
}

// Proto identifies the transport protocol for a stream.
type Proto uint8

const (
	ProtoTCP Proto = 0x01
	ProtoUDP Proto = 0x03
)

// AddrType identifies the address format.
type AddrType uint8

const (
	AddrIPv4   AddrType = 0x01 // 4-byte IPv4 address
	AddrDomain AddrType = 0x03 // 1-byte length prefix + hostname bytes
	AddrIPv6   AddrType = 0x04 // 16-byte IPv6 address
)

// OpenPayload is the payload of a FrameOpen frame.
// It describes the destination for a new stream.
type OpenPayload struct {
	Proto    Proto    // TCP or UDP
	AddrType AddrType // IPv4, Domain, IPv6
	Addr     string   // "93.184.216.34" or "example.com" or "2001:db8::1"
	Port     uint16
}

// EncodeOpenPayload serializes an OpenPayload into bytes suitable
// for use as Frame.Payload in a FrameOpen frame.
//
// Wire format:
//
//	[Proto:1][AddrType:1][Address:variable][Port:2 big-endian]
//
// Address encoding by AddrType:
//
//	AddrIPv4  (0x01): 4 bytes (net.IP.To4)
//	AddrDomain(0x03): 1-byte length + hostname bytes (max 255)
//	AddrIPv6  (0x04): 16 bytes (net.IP.To16)
func EncodeOpenPayload(op *OpenPayload) ([]byte, error) {
	var addrBytes []byte

	switch op.AddrType {
	case AddrIPv4:
		ip := net.ParseIP(op.Addr)
		if ip == nil {
			return nil, fmt.Errorf("encode open payload: invalid IPv4 address %q", op.Addr)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("encode open payload: %q is not a valid IPv4 address", op.Addr)
		}
		addrBytes = ip4

	case AddrDomain:
		n := len(op.Addr)
		if n < 1 || n > 255 {
			return nil, fmt.Errorf("encode open payload: domain length %d out of range [1,255]", n)
		}
		addrBytes = make([]byte, 1+n)
		addrBytes[0] = byte(n)
		copy(addrBytes[1:], op.Addr)

	case AddrIPv6:
		ip := net.ParseIP(op.Addr)
		if ip == nil {
			return nil, fmt.Errorf("encode open payload: invalid IPv6 address %q", op.Addr)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("encode open payload: %q is an IPv4 address, not IPv6", op.Addr)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("encode open payload: %q cannot be converted to 16-byte form", op.Addr)
		}
		addrBytes = ip16

	default:
		return nil, fmt.Errorf("encode open payload: unknown address type 0x%02x", op.AddrType)
	}

	// Proto(1) + AddrType(1) + addrBytes + Port(2)
	buf := make([]byte, 2+len(addrBytes)+2)
	buf[0] = byte(op.Proto)
	buf[1] = byte(op.AddrType)
	copy(buf[2:], addrBytes)
	binary.BigEndian.PutUint16(buf[2+len(addrBytes):], op.Port)
	return buf, nil
}

// DecodeOpenPayload deserializes bytes into an OpenPayload.
// Returns ErrFrameCorrupt if the data is malformed.
func DecodeOpenPayload(data []byte) (*OpenPayload, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("decode open payload: data too short (%d bytes): %w", len(data), ErrFrameCorrupt)
	}

	op := &OpenPayload{
		Proto:    Proto(data[0]),
		AddrType: AddrType(data[1]),
	}
	rest := data[2:]

	switch op.AddrType {
	case AddrIPv4:
		if len(rest) < 4+2 {
			return nil, fmt.Errorf("decode open payload: IPv4 data too short: %w", ErrFrameCorrupt)
		}
		op.Addr = net.IP(rest[:4]).String()
		rest = rest[4:]

	case AddrDomain:
		if len(rest) < 1 {
			return nil, fmt.Errorf("decode open payload: missing domain length: %w", ErrFrameCorrupt)
		}
		n := int(rest[0])
		rest = rest[1:]
		if n == 0 || len(rest) < n+2 {
			return nil, fmt.Errorf("decode open payload: domain data too short: %w", ErrFrameCorrupt)
		}
		op.Addr = string(rest[:n])
		rest = rest[n:]

	case AddrIPv6:
		if len(rest) < 16+2 {
			return nil, fmt.Errorf("decode open payload: IPv6 data too short: %w", ErrFrameCorrupt)
		}
		op.Addr = net.IP(rest[:16]).String()
		rest = rest[16:]

	default:
		return nil, fmt.Errorf("decode open payload: unknown address type 0x%02x: %w", op.AddrType, ErrFrameCorrupt)
	}

	op.Port = binary.BigEndian.Uint16(rest[:2])
	return op, nil
}
