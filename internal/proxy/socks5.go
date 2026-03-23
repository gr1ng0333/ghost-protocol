package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Stream is the tunnel stream interface. Matches mux.Stream but redefined
// here to avoid circular import (proxy → mux is allowed, but we use the
// interface to decouple).
type Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	ID() uint32
}

// StreamOpener is a function that opens a new Ghost tunnel stream.
type StreamOpener func(ctx context.Context, addr string, port uint16) (Stream, error)

// SOCKS5Server accepts local SOCKS5 connections and forwards them
// through the Ghost tunnel.
type SOCKS5Server interface {
	ListenAndServe(ctx context.Context, addr string, tunnel StreamOpener) error
	Close() error
}

const (
	socks5Version = 0x05

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess           = 0x00
	repGeneralFailure    = 0x01
	repConnectionRefused = 0x05
	repCmdNotSupported   = 0x07
	repAddrNotSupported  = 0x08

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF
)

// socks5Conn handles a single SOCKS5 client connection.
type socks5Conn struct {
	conn net.Conn
}

// Handshake performs SOCKS5 method negotiation (RFC 1928 Section 3).
// Only supports method 0x00 (no authentication).
// Returns nil if negotiation succeeds.
func (s *socks5Conn) Handshake() error {
	// Read: VER, NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return fmt.Errorf("read handshake header: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		return fmt.Errorf("no auth methods offered")
	}

	// Read method list.
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(s.conn, methods); err != nil {
		return fmt.Errorf("read auth methods: %w", err)
	}

	// Check if no-auth (0x00) is offered.
	found := false
	for _, m := range methods {
		if m == methodNoAuth {
			found = true
			break
		}
	}

	if !found {
		// Reply with no acceptable methods.
		s.conn.Write([]byte{socks5Version, methodNoAcceptable})
		return fmt.Errorf("no supported auth method (need 0x00)")
	}

	// Reply: VER, METHOD=0x00
	if _, err := s.conn.Write([]byte{socks5Version, methodNoAuth}); err != nil {
		return fmt.Errorf("write handshake reply: %w", err)
	}
	return nil
}

// ReadRequest reads the SOCKS5 CONNECT request (RFC 1928 Section 4).
// Only supports CMD 0x01 (CONNECT). Returns error for BIND (0x02) and
// UDP-ASSOCIATE (0x03).
// Supports ATYP: 0x01 (IPv4), 0x03 (domain name), 0x04 (IPv6).
// Domain names are passed through as-is (DNS resolution on Ghost server).
func (s *socks5Conn) ReadRequest() (addr string, port uint16, err error) {
	// VER, CMD, RSV, ATYP
	header := make([]byte, 4)
	if _, err = io.ReadFull(s.conn, header); err != nil {
		return "", 0, fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socks5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}

	cmd := header[1]
	if cmd != cmdConnect {
		rep := repCmdNotSupported
		s.SendReply(byte(rep), "0.0.0.0", 0)
		return "", 0, fmt.Errorf("unsupported command: 0x%02x", cmd)
	}

	atyp := header[3]
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err = io.ReadFull(s.conn, buf); err != nil {
			return "", 0, fmt.Errorf("read IPv4 addr: %w", err)
		}
		addr = net.IP(buf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(s.conn, lenBuf); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domLen := int(lenBuf[0])
		domain := make([]byte, domLen)
		if _, err = io.ReadFull(s.conn, domain); err != nil {
			return "", 0, fmt.Errorf("read domain name: %w", err)
		}
		addr = string(domain)

	case atypIPv6:
		buf := make([]byte, 16)
		if _, err = io.ReadFull(s.conn, buf); err != nil {
			return "", 0, fmt.Errorf("read IPv6 addr: %w", err)
		}
		addr = net.IP(buf).String()

	default:
		s.SendReply(repAddrNotSupported, "0.0.0.0", 0)
		return "", 0, fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}

	// Read port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(s.conn, portBuf); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBuf)

	return addr, port, nil
}

// SendReply sends a SOCKS5 reply (RFC 1928 Section 6).
// rep codes: 0x00=success, 0x01=general failure, 0x05=connection refused, etc.
func (s *socks5Conn) SendReply(rep byte, bindAddr string, bindPort uint16) error {
	// VER, REP, RSV, ATYP(0x01), BND.ADDR(4 bytes), BND.PORT(2 bytes)
	reply := make([]byte, 10)
	reply[0] = socks5Version
	reply[1] = rep
	reply[2] = 0x00 // RSV
	reply[3] = atypIPv4

	ip := net.ParseIP(bindAddr)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			copy(reply[4:8], ip4)
		}
	}
	// If ip is nil or not IPv4, reply[4:8] stays all zeros (0.0.0.0).

	binary.BigEndian.PutUint16(reply[8:10], bindPort)

	if _, err := s.conn.Write(reply); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}
	return nil
}
