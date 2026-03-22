package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// splice forwards a connection to a fallback backend (e.g., Caddy on localhost:8080).
// It replays the peeked bytes (the raw ClientHello) to the backend first,
// then copies bytes bidirectionally between client and backend until one side closes.
//
// This makes Ghost transparent to Caddy: Caddy sees a normal TLS connection
// as if the client connected directly. Caddy terminates TLS and serves the website.
func splice(ctx context.Context, client net.Conn, peeked []byte, fallbackAddr string) error {
	// Clear any deadlines from the peek phase.
	client.SetDeadline(time.Time{})

	// Dial the fallback backend.
	var d net.Dialer
	backend, err := d.DialContext(ctx, "tcp", fallbackAddr)
	if err != nil {
		return fmt.Errorf("splice: dial fallback %s: %w", fallbackAddr, err)
	}
	defer backend.Close()
	defer client.Close()

	// Cancel both connections when context is done.
	go func() {
		<-ctx.Done()
		deadline := time.Now().Add(time.Second)
		client.SetDeadline(deadline)
		backend.SetDeadline(deadline)
	}()

	// Combined reader: peeked bytes first, then live client data.
	clientReader := io.MultiReader(bytes.NewReader(peeked), client)

	var wg sync.WaitGroup
	wg.Add(2)

	// client → backend
	go func() {
		defer wg.Done()
		_, err := io.Copy(backend, clientReader)
		if err != nil {
			slog.Debug("splice: client→backend finished", "err", err)
		}
		closeWrite(backend)
	}()

	// backend → client
	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		if err != nil {
			slog.Debug("splice: backend→client finished", "err", err)
		}
		closeWrite(client)
	}()

	wg.Wait()
	return nil
}

// closeWrite sends TCP FIN on the write side without closing the read side.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
