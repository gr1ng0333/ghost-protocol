//go:build linux

package proxy

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSetupRouting_InvalidServerAddr(t *testing.T) {
	err := SetupRouting("ghost0", "10.0.85.1", "not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid server address")
	}
	if !strings.Contains(err.Error(), "must be an IP") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSetupRouting_InvalidServerAddr_Hostname(t *testing.T) {
	err := SetupRouting("ghost0", "10.0.85.1", "example.com")
	if err == nil {
		t.Fatal("expected error for hostname server address")
	}
	if !strings.Contains(err.Error(), "must be an IP") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetupRouting_InvalidServerAddr_Empty(t *testing.T) {
	err := SetupRouting("ghost0", "10.0.85.1", "")
	if err == nil {
		t.Fatal("expected error for empty server address")
	}
}

func TestRestoreRouting_NotConfigured(t *testing.T) {
	// RestoreRouting when nothing is configured should be a safe no-op.
	// Must not panic.
	RestoreRouting()
}

func TestRouteConstants(t *testing.T) {
	if ghostTable != "100" {
		t.Errorf("ghostTable = %q, want %q", ghostTable, "100")
	}
	if prefServer != "100" {
		t.Errorf("prefServer = %q, want %q", prefServer, "100")
	}
	if prefLAN != "110" {
		t.Errorf("prefLAN = %q, want %q", prefLAN, "110")
	}
	if prefMainNoDefault != "120" {
		t.Errorf("prefMainNoDefault = %q, want %q", prefMainNoDefault, "120")
	}
	if prefGhost != "130" {
		t.Errorf("prefGhost = %q, want %q", prefGhost, "130")
	}
}

func TestRunCommand_NonExistent(t *testing.T) {
	err := run("nonexistent_command_xyz_12345")
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestRunCommand_FailingCommand(t *testing.T) {
	err := run("ip", "link", "show", "nonexistent_device_xyz_99")
	if err == nil {
		t.Fatal("expected error for failing ip command")
	}
	if !strings.Contains(err.Error(), "ip") {
		t.Errorf("error should mention command name: %v", err)
	}
}

// --- Integration tests (require root + Linux) ---

func hasRouteInTable(t *testing.T, table string) bool {
	t.Helper()
	out, err := exec.Command("ip", "-4", "route", "show", "table", table).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

func TestSetupRouting_And_Restore(t *testing.T) {
	if os.Getenv("GHOST_TUN_TESTS") != "1" {
		t.Skip("skipping TUN test: set GHOST_TUN_TESTS=1 and run as root")
	}

	// Create TUN interface via ip tuntap.
	tunName := "ghostrt0"
	if err := run("ip", "tuntap", "add", "dev", tunName, "mode", "tun"); err != nil {
		t.Fatalf("failed to create TUN: %v", err)
	}
	t.Cleanup(func() {
		RestoreRouting()
		_ = run("ip", "link", "del", tunName)
	})

	if err := SetupRouting(tunName, "10.0.85.1", "127.0.0.2"); err != nil {
		t.Fatalf("SetupRouting failed: %v", err)
	}

	// Verify rules exist.
	out, err := exec.Command("ip", "-4", "rule", "show").Output()
	if err != nil {
		t.Fatalf("ip rule show failed: %v", err)
	}
	rules := string(out)
	for _, pref := range []string{"100", "110", "120", "130"} {
		if !strings.Contains(rules, pref+":") {
			t.Errorf("missing ip rule with pref %s", pref)
		}
	}

	// Verify Ghost table has a route.
	if !hasRouteInTable(t, ghostTable) {
		t.Error("Ghost routing table is empty after SetupRouting")
	}

	// Restore routing.
	RestoreRouting()

	// Verify rules are gone.
	out, err = exec.Command("ip", "-4", "rule", "show").Output()
	if err != nil {
		t.Fatalf("ip rule show failed: %v", err)
	}
	rules = string(out)
	for _, pref := range []string{"100:", "130:"} {
		if strings.Contains(rules, pref) {
			t.Errorf("ip rule with pref %s still exists after RestoreRouting", pref)
		}
	}

	// Verify table is empty.
	if hasRouteInTable(t, ghostTable) {
		t.Error("Ghost routing table not empty after RestoreRouting")
	}
}

func TestSetupRouting_AlreadyConfigured(t *testing.T) {
	if os.Getenv("GHOST_TUN_TESTS") != "1" {
		t.Skip("skipping TUN test: set GHOST_TUN_TESTS=1 and run as root")
	}

	tunName := "ghostrt1"
	if err := run("ip", "tuntap", "add", "dev", tunName, "mode", "tun"); err != nil {
		t.Fatalf("failed to create TUN: %v", err)
	}
	t.Cleanup(func() {
		RestoreRouting()
		_ = run("ip", "link", "del", tunName)
	})

	if err := SetupRouting(tunName, "10.0.85.1", "127.0.0.2"); err != nil {
		t.Fatalf("first SetupRouting failed: %v", err)
	}

	// Second call should fail with "already configured".
	err := SetupRouting(tunName, "10.0.85.1", "127.0.0.2")
	if err == nil {
		t.Fatal("expected error for duplicate SetupRouting")
	}
	if !strings.Contains(err.Error(), "already configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRoutingBypass_ServerAddr(t *testing.T) {
	if os.Getenv("GHOST_TUN_TESTS") != "1" {
		t.Skip("skipping TUN test: set GHOST_TUN_TESTS=1 and run as root")
	}

	tunName := "ghostrt2"
	serverAddr := "198.51.100.1"
	if err := run("ip", "tuntap", "add", "dev", tunName, "mode", "tun"); err != nil {
		t.Fatalf("failed to create TUN: %v", err)
	}
	t.Cleanup(func() {
		RestoreRouting()
		_ = run("ip", "link", "del", tunName)
	})

	if err := SetupRouting(tunName, "10.0.85.1", serverAddr); err != nil {
		t.Fatalf("SetupRouting failed: %v", err)
	}

	// Check that the server address does NOT route through the TUN.
	out, err := exec.Command("ip", "-4", "route", "get", serverAddr).Output()
	if err != nil {
		t.Fatalf("ip route get failed: %v", err)
	}
	if strings.Contains(string(out), tunName) {
		t.Errorf("server addr %s should bypass TUN, but routes through %s: %s",
			serverAddr, tunName, string(out))
	}
}

func TestRoutingBypass_LAN(t *testing.T) {
	if os.Getenv("GHOST_TUN_TESTS") != "1" {
		t.Skip("skipping TUN test: set GHOST_TUN_TESTS=1 and run as root")
	}

	tunName := "ghostrt3"
	if err := run("ip", "tuntap", "add", "dev", tunName, "mode", "tun"); err != nil {
		t.Fatalf("failed to create TUN: %v", err)
	}
	t.Cleanup(func() {
		RestoreRouting()
		_ = run("ip", "link", "del", tunName)
	})

	if err := SetupRouting(tunName, "10.0.85.1", "127.0.0.2"); err != nil {
		t.Fatalf("SetupRouting failed: %v", err)
	}

	// LAN address should NOT go through the TUN.
	out, err := exec.Command("ip", "-4", "route", "get", "192.168.1.1").Output()
	if err != nil {
		t.Fatalf("ip route get failed: %v", err)
	}
	if strings.Contains(string(out), tunName) {
		t.Errorf("LAN addr 192.168.1.1 should bypass TUN, but routes through %s: %s",
			tunName, string(out))
	}
}
