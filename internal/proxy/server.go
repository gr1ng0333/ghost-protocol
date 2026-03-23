package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
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

	slog.Info("socks5 connect", "remote", clientConn.RemoteAddr(), "dest", addr, "port", port)

	stream, err := tunnel(ctx, addr, port)
	if err != nil {
		sc.SendReply(repConnectionRefused, "0.0.0.0", 0)
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

// relay performs bidirectional data copy between two ReadWriteClosers.
// When either side closes or errors, both sides are closed.
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}
