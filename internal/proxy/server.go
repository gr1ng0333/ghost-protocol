package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

type socks5Server struct {
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// NewSOCKS5Server creates a new SOCKS5Server.
func NewSOCKS5Server() SOCKS5Server {
	return &socks5Server{}
}

// ListenAndServe starts the SOCKS5 server on addr and forwards connections
// through the provided tunnel StreamOpener.
func (s *socks5Server) ListenAndServe(ctx context.Context, addr string, tunnel StreamOpener) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	slog.Info("socks5 server listening", "addr", addr)

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			slog.Warn("socks5 accept error", "err", err)
			continue
		}
		go s.handleConn(ctx, conn, tunnel)
	}
}

func (s *socks5Server) handleConn(ctx context.Context, clientConn net.Conn, tunnel StreamOpener) {
	defer clientConn.Close()

	// Set deadline for SOCKS5 handshake phase to prevent slow-client DoS.
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	sc := &socks5Conn{conn: clientConn}

	if err := sc.Handshake(); err != nil {
		slog.Warn("socks5 handshake failed", "remote", clientConn.RemoteAddr(), "err", err)
		return
	}

	addr, port, err := sc.ReadRequest()
	if err != nil {
		slog.Warn("socks5 request failed", "remote", clientConn.RemoteAddr(), "err", err)
		return
	}

	// Clear deadline for data relay phase.
	clientConn.SetDeadline(time.Time{})

	slog.Info("socks5 connect", "remote", clientConn.RemoteAddr(), "dest", addr, "port", port)

	stream, err := tunnel(ctx, addr, port)
	if err != nil {
		if replyErr := sc.SendReply(repConnectionRefused, "0.0.0.0", 0); replyErr != nil {
			slog.Warn("socks5 connection-refused reply failed", "err", replyErr)
		}
		slog.Warn("tunnel open failed", "dest", addr, "port", port, "err", err)
		return
	}
	defer stream.Close()

	if err := sc.SendReply(repSuccess, "0.0.0.0", 0); err != nil {
		slog.Warn("socks5 reply failed", "err", err)
		return
	}

	slog.Debug("socks5 relay start", "stream", stream.ID(), "dest", addr, "port", port)
	relay(clientConn, stream)
	slog.Debug("socks5 relay done", "stream", stream.ID())
}

// Close stops the SOCKS5 server by closing the listener.
func (s *socks5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// halfCloser is implemented by connections that support closing the
// write direction independently (e.g. *net.TCPConn, mux *stream).
type halfCloser interface {
	CloseWrite() error
}

// relay performs bidirectional data copy between two ReadWriteClosers.
// It uses half-close when supported: when one direction reaches EOF,
// the write side of the other connection is closed while the reverse
// direction continues. Full cleanup happens when both directions finish.
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)

	// a ← b: read from b, write to a.
	go func() {
		io.Copy(a, b)
		// b sent EOF — signal a that no more data is coming.
		if hc, ok := a.(halfCloser); ok {
			hc.CloseWrite()
		} else {
			a.Close()
		}
		done <- struct{}{}
	}()

	// b ← a: read from a, write to b.
	go func() {
		io.Copy(b, a)
		// a sent EOF — signal b that no more data is coming.
		if hc, ok := b.(halfCloser); ok {
			hc.CloseWrite()
		} else {
			b.Close()
		}
		done <- struct{}{}
	}()

	// Wait for both directions to finish, then full-close both sides.
	<-done
	<-done
	a.Close()
	b.Close()
}
