//go:build linux

package main

import "ghost/internal/proxy"

func newTunDevice(name, tunIP, serverAddr string) proxy.TunDevice {
	return proxy.NewTunDevice(name, tunIP, serverAddr)
}
