//go:build !linux

package ghost

import (
	"context"
	"fmt"
	"os"

	"ghost/internal/proxy"
)

// setupNetstack is not supported on non-Linux platforms.
// Android (Linux kernel) is the target; this stub allows compilation
// and testing of non-netstack code on other platforms.
func setupNetstack(_ context.Context, _ *os.File, _ uint32, _ proxy.StreamOpener) (func(), error) {
	return nil, fmt.Errorf("netstack: not supported on this platform")
}
