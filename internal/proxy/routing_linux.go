//go:build linux

package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	ghostTable        = "100" // dedicated routing table for Ghost
	prefServer        = "100" // ip rule priority: Ghost server bypass
	prefIPv6Block     = "100" // ip -6 rule priority: block all IPv6
	prefLAN           = "110" // ip rule priority: LAN bypass
	prefMainNoDefault = "120" // ip rule priority: main table without default
	prefGhost         = "130" // ip rule priority: Ghost tunnel table
)

// routeState holds the routing configuration for cleanup.
type routeState struct {
	mu         sync.Mutex
	configured bool
	tunName    string
	serverAddr string // Ghost server IP (bypass TUN)
	origGW     string // original default gateway IP
	origDev    string // original default gateway device
}

var routing routeState

// SetupRouting configures policy-based routing to send all traffic
// through the TUN device, except:
//   - Traffic to the Ghost server IP (must use real interface to avoid loop)
//   - LAN traffic (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Loopback (127.0.0.0/8)
//   - Link-local (169.254.0.0/16)
//
// This uses Linux policy routing (ip rule + separate table), following
// the WireGuard wg-quick pattern. The main routing table is NOT modified.
//
// Requires root or CAP_NET_ADMIN.
func SetupRouting(tunName, tunIP, serverAddr string) error {
	routing.mu.Lock()
	defer routing.mu.Unlock()

	if routing.configured {
		return fmt.Errorf("routing already configured")
	}

	// Extract host from server address (strip port if present)
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		// No port in address, use as-is
		host = serverAddr
	}

	// Resolve hostname to IP if needed
	serverIP := host
	if net.ParseIP(host) == nil {
		ips, lookupErr := net.LookupHost(host)
		if lookupErr != nil {
			return fmt.Errorf("SetupRouting: resolve server %q: %w", host, lookupErr)
		}
		serverIP = ips[0]
	}

	// Detect current default gateway (needed for server bypass route)
	gw, dev, err := detectDefaultGateway()
	if err != nil {
		return fmt.Errorf("SetupRouting: detect gateway: %w", err)
	}

	routing.origGW = gw
	routing.origDev = dev
	routing.tunName = tunName
	routing.serverAddr = serverIP

	// Configure TUN interface IP and bring it up
	if err := run("ip", "addr", "add", tunIP+"/24", "dev", tunName); err != nil {
		return fmt.Errorf("SetupRouting: add addr: %w", err)
	}
	if err := run("ip", "link", "set", tunName, "up"); err != nil {
		return fmt.Errorf("SetupRouting: link up: %w", err)
	}

	// Add default route in Ghost table via TUN
	if err := run("ip", "-4", "route", "replace", "default", "dev", tunName, "table", ghostTable); err != nil {
		return fmt.Errorf("SetupRouting: add ghost route: %w", err)
	}

	// Rule: Ghost server IP → lookup main (bypass TUN)
	if err := run("ip", "-4", "rule", "add", "pref", prefServer,
		"to", serverIP+"/32", "lookup", "main"); err != nil {
		return fmt.Errorf("SetupRouting: server rule: %w", err)
	}

	// Rules: RFC1918 + loopback + link-local → lookup main
	lanRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}
	for _, cidr := range lanRanges {
		if err := run("ip", "-4", "rule", "add", "pref", prefLAN,
			"to", cidr, "lookup", "main"); err != nil {
			return fmt.Errorf("SetupRouting: LAN rule %s: %w", cidr, err)
		}
	}

	// Rule: use main table but suppress its default route
	if err := run("ip", "-4", "rule", "add", "pref", prefMainNoDefault,
		"lookup", "main", "suppress_prefixlength", "0"); err != nil {
		return fmt.Errorf("SetupRouting: main-no-default rule: %w", err)
	}

	// Rule: everything else → Ghost table
	if err := run("ip", "-4", "rule", "add", "pref", prefGhost,
		"lookup", ghostTable); err != nil {
		return fmt.Errorf("SetupRouting: ghost rule: %w", err)
	}

	// Block IPv6 traffic to prevent leaks (Ghost tunnel is IPv4-only)
	if err := run("ip", "-6", "rule", "add", "pref", prefIPv6Block, "prohibit"); err != nil {
		return fmt.Errorf("SetupRouting: ipv6 block rule: %w", err)
	}

	// Set up DNS through tunnel
	if err := setupDNS(tunName); err != nil {
		slog.Warn("SetupRouting: DNS setup failed (non-fatal)", "error", err)
	}

	routing.configured = true

	slog.Info("routing configured",
		"tun", tunName,
		"server_bypass", serverIP,
		"gateway", gw,
		"device", dev,
	)

	return nil
}

// RestoreRouting undoes all routing changes made by SetupRouting.
// Safe to call multiple times (idempotent).
// Does not return error — logs warnings for individual failures
// but always attempts all cleanup steps.
func RestoreRouting() {
	routing.mu.Lock()
	defer routing.mu.Unlock()

	if !routing.configured {
		return
	}

	// Delete ip rules by priority (ignore errors — may already be gone)
	for _, pref := range []string{prefServer, prefLAN, prefMainNoDefault, prefGhost} {
		// LAN has multiple rules with same pref, delete in loop until error
		for {
			if err := run("ip", "-4", "rule", "del", "pref", pref); err != nil {
				break
			}
		}
	}

	// Remove IPv6 block rule
	_ = run("ip", "-6", "rule", "del", "pref", prefIPv6Block, "prohibit")

	// Flush Ghost routing table
	_ = run("ip", "-4", "route", "flush", "table", ghostTable)

	// Restore DNS
	restoreDNS(routing.tunName)

	// Bring TUN interface down
	_ = run("ip", "link", "set", routing.tunName, "down")

	routing.configured = false

	slog.Info("routing restored")
}

// detectDefaultGateway parses "ip -4 route show default" to find the
// current default gateway IP and device.
func detectDefaultGateway() (gateway, device string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route show default: %w", err)
	}
	// Parse: "default via 192.168.1.1 dev eth0 ..."
	fields := strings.Fields(strings.TrimSpace(string(out)))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gateway = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			device = fields[i+1]
		}
	}
	if gateway == "" || device == "" {
		return "", "", fmt.Errorf("could not parse default route from: %s", string(out))
	}
	return gateway, device, nil
}

// setupDNS configures DNS to go through the tunnel.
// Tries systemd-resolved first (resolvectl), falls back gracefully.
func setupDNS(tunName string) error {
	if err := run("resolvectl", "dns", tunName, "1.1.1.1", "1.0.0.1"); err == nil {
		_ = run("resolvectl", "domain", tunName, "~.")
		_ = run("resolvectl", "default-route", tunName, "true")
		slog.Info("dns configured via systemd-resolved", "tun", tunName)
		return nil
	}

	slog.Warn("systemd-resolved not available, DNS may leak")
	return nil
}

// restoreDNS undoes DNS changes.
func restoreDNS(tunName string) {
	if err := run("resolvectl", "revert", tunName); err == nil {
		slog.Info("dns restored via systemd-resolved")
		return
	}
}

// run executes a command and returns an error if it fails.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
