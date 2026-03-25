//go:build !linux

package main

import "ghost/internal/proxy"

func newTunDevice(_, _, _, _ string) proxy.TunDevice {
	return nil
}
