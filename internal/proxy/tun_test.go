//go:build linux

package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mockTunnel is a StreamOpener that always returns an error.
func mockTunnel(_ context.Context, _ string, _ uint16) (Stream, error) {
	return nil, fmt.Errorf("mock: tunnel not available")
}

func TestNewTunDevice_Fields(t *testing.T) {
	dev := NewTunDevice("ghost0", "10.0.85.1", "1.2.3.4")
	if dev == nil {
		t.Fatal("NewTunDevice returned nil")
	}

	// Verify the concrete type has expected fields.
	td, ok := dev.(*tunDevice)
	if !ok {
		t.Fatal("NewTunDevice did not return *tunDevice")
	}
	if td.name != "ghost0" {
		t.Errorf("name = %q, want %q", td.name, "ghost0")
	}
	if td.tunIP != "10.0.85.1" {
		t.Errorf("tunIP = %q, want %q", td.tunIP, "10.0.85.1")
	}
	if td.serverAddr != "1.2.3.4" {
		t.Errorf("serverAddr = %q, want %q", td.serverAddr, "1.2.3.4")
	}
	if td.mtu != 1500 {
		t.Errorf("mtu = %d, want 1500", td.mtu)
	}
	if td.closed {
		t.Error("closed should be false on new device")
	}
	if td.tunFD != -1 {
		t.Errorf("tunFD = %d, want -1 on new device", td.tunFD)
	}
}

func TestNewTunDevice_Interface(t *testing.T) {
	var iface TunDevice = NewTunDevice("tun0", "10.0.0.1", "8.8.8.8")
	if iface == nil {
		t.Fatal("NewTunDevice returned nil")
	}
}

func TestTunDevice_StopIdempotent(t *testing.T) {
	dev := NewTunDevice("ghost0", "10.0.85.1", "1.2.3.4")

	// Stop without Start — should be a no-op, no panic.
	if err := dev.Stop(); err != nil {
		t.Errorf("first Stop returned error: %v", err)
	}
	// Second Stop — should still be safe.
	if err := dev.Stop(); err != nil {
		t.Errorf("second Stop returned error: %v", err)
	}
}

func TestTunDevice_StopBeforeStart(t *testing.T) {
	dev := NewTunDevice("ghost0", "10.0.85.1", "1.2.3.4")

	// Verify Stop is safe when Start was never called (no stack, no cancel).
	td := dev.(*tunDevice)
	if td.stack != nil {
		t.Error("stack should be nil before Start")
	}
	if err := dev.Stop(); err != nil {
		t.Errorf("Stop returned error: %v", err)
	}
}

// --- Integration tests (require root + Linux) ---

func skipUnlessTUN(t *testing.T) {
	t.Helper()
	if os.Getenv("GHOST_TUN_TESTS") != "1" {
		t.Skip("skipping TUN test: set GHOST_TUN_TESTS=1 and run as root")
	}
}

func hasIPRule(t *testing.T, pref string) bool {
	t.Helper()
	out, err := exec.Command("ip", "-4", "rule", "show").Output()
	if err != nil {
		t.Fatalf("ip rule show failed: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, pref+":") {
			return true
		}
	}
	return false
}

func TestTun_CreateAndDestroy(t *testing.T) {
	skipUnlessTUN(t)

	dev := NewTunDevice("ghosttest0", "10.0.85.1", "127.0.0.2")
	t.Cleanup(func() {
		dev.Stop()
	})

	err := dev.Start(context.Background(), mockTunnel)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify TUN interface exists.
	out, err := exec.Command("ip", "link", "show", "ghosttest0").Output()
	if err != nil {
		t.Fatalf("TUN interface not found: %v", err)
	}
	if !strings.Contains(string(out), "ghosttest0") {
		t.Errorf("ip link show did not contain ghosttest0: %s", out)
	}

	// Stop and verify cleanup.
	if err := dev.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestTun_FullPipeline(t *testing.T) {
	skipUnlessTUN(t)

	dev := NewTunDevice("ghosttest0", "10.0.85.1", "127.0.0.2")
	t.Cleanup(func() {
		dev.Stop()
	})

	err := dev.Start(context.Background(), mockTunnel)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify routing rules were created.
	for _, pref := range []string{"100", "110", "120", "130"} {
		if !hasIPRule(t, pref) {
			t.Errorf("expected ip rule with pref %s after Start", pref)
		}
	}

	// Stop device (restores routing).
	if err := dev.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Verify routing rules were removed.
	for _, pref := range []string{"100", "110", "120", "130"} {
		if hasIPRule(t, pref) {
			t.Errorf("ip rule with pref %s still exists after Stop", pref)
		}
	}
}
