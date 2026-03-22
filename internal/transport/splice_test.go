package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair creates a pair of connected TCP connections using a localhost listener.
// This is preferred over net.Pipe() because real TCP connections support CloseWrite.
func tcpPair(t *testing.T) (client, remote net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcpPair listen: %v", err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- c
	}()

	client, err = net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("tcpPair dial: %v", err)
	}

	select {
	case remote = <-connCh:
	case <-time.After(2 * time.Second):
		client.Close()
		t.Fatal("tcpPair: timeout waiting for accept")
	}
	return client, remote
}

func TestSplice_BidirectionalCopy(t *testing.T) {
	peeked := []byte("PEEKED-HELLO")
	clientPayload := []byte("-FOLLOWED-BY-LIVE-DATA")
	backendResponse := []byte("BACKEND-RESPONSE")

	// Start a backend that reads all data and sends a response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	backendReceived := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		data, _ := io.ReadAll(conn)
		backendReceived <- data

		conn.Write(backendResponse)
		closeWrite(conn)
	}()

	// Use real TCP pair so CloseWrite works properly.
	clientConn, clientRemote := tcpPair(t)
	defer clientConn.Close()

	ctx := context.Background()
	spliceDone := make(chan error, 1)
	go func() {
		spliceDone <- splice(ctx, clientRemote, peeked, ln.Addr().String())
	}()

	// Client writes live data, then closes write side (TCP half-close).
	clientConn.Write(clientPayload)
	closeWrite(clientConn)

	// Read the backend's response from the client side.
	got, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client ReadAll: %v", err)
	}
	if !bytes.Equal(got, backendResponse) {
		t.Errorf("client received %q, want %q", got, backendResponse)
	}

	// Verify the backend received peeked + live data.
	select {
	case data := <-backendReceived:
		want := append(peeked, clientPayload...)
		if !bytes.Equal(data, want) {
			t.Errorf("backend received %q, want %q", data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for backend data")
	}

	// Splice should complete without error.
	select {
	case err := <-spliceDone:
		if err != nil {
			t.Fatalf("splice: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for splice to complete")
	}
}

func TestSplice_PeekedBytesReplayedFirst(t *testing.T) {
	peeked := []byte("CLIENTHELLO-BYTES-HERE")
	liveData := []byte("ADDITIONAL-LIVE-DATA")

	// Backend reads exactly len(peeked) bytes first, verifies, then reads rest.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type readResult struct {
		first []byte
		rest  []byte
	}
	results := make(chan readResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		first := make([]byte, len(peeked))
		io.ReadFull(conn, first)

		rest, _ := io.ReadAll(conn)
		results <- readResult{first: first, rest: rest}
	}()

	clientConn, clientRemote := tcpPair(t)
	defer clientConn.Close()

	ctx := context.Background()
	spliceDone := make(chan error, 1)
	go func() {
		spliceDone <- splice(ctx, clientRemote, peeked, ln.Addr().String())
	}()

	clientConn.Write(liveData)
	clientConn.Close()

	select {
	case r := <-results:
		if !bytes.Equal(r.first, peeked) {
			t.Errorf("first bytes = %q, want %q", r.first, peeked)
		}
		if !bytes.Equal(r.rest, liveData) {
			t.Errorf("rest = %q, want %q", r.rest, liveData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for backend results")
	}

	select {
	case err := <-spliceDone:
		if err != nil {
			t.Fatalf("splice: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for splice")
	}
}

func TestSplice_OneDirectionClose(t *testing.T) {
	backendResponse := []byte("RESPONSE-AFTER-CLIENT-CLOSE")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read until client EOF, then send response.
		io.ReadAll(conn)
		conn.Write(backendResponse)
		closeWrite(conn)
	}()

	clientConn, clientRemote := tcpPair(t)
	defer clientConn.Close()

	ctx := context.Background()
	spliceDone := make(chan error, 1)
	go func() {
		spliceDone <- splice(ctx, clientRemote, []byte("PEEK"), ln.Addr().String())
	}()

	// Client closes write side immediately — backend should still respond.
	closeWrite(clientConn)

	got, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client ReadAll: %v", err)
	}
	if !bytes.Equal(got, backendResponse) {
		t.Errorf("client received %q, want %q", got, backendResponse)
	}

	select {
	case err := <-spliceDone:
		if err != nil {
			t.Fatalf("splice: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for splice")
	}
}

func TestSplice_ContextCancellation(t *testing.T) {
	// Start a backend that just blocks (never reads or writes).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Block indefinitely.
		select {}
	}()

	clientConn, clientRemote := tcpPair(t)
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	spliceDone := make(chan error, 1)
	go func() {
		spliceDone <- splice(ctx, clientRemote, []byte("PEEK"), ln.Addr().String())
	}()

	// Let splice establish connections.
	time.Sleep(50 * time.Millisecond)

	// Cancel context — splice should return promptly.
	cancel()

	select {
	case <-spliceDone:
		// Splice returned — success. Error is acceptable (deadline exceeded).
	case <-time.After(5 * time.Second):
		t.Fatal("splice did not return after context cancellation")
	}
}
