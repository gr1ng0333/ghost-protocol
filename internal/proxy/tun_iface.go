package proxy

import "context"

// TunDevice manages a TUN interface backed by a userspace TCP/IP
// stack. Intercepted TCP streams are tunneled through Ghost via the
// StreamOpener provided to Start.
type TunDevice interface {
	Start(ctx context.Context, tunnel StreamOpener) error
	Stop() error
}
