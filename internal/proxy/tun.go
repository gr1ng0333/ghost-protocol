//go:build linux

package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunDevice implements TunDevice using gVisor netstack.
// It creates a Linux TUN interface, feeds raw IP packets into gVisor's
// userspace TCP/IP stack, which reconstructs TCP streams. Each TCP
// connection becomes a tunnel stream via StreamOpener.
type tunDevice struct {
	name       string       // TUN device name, e.g. "ghost0"
	mtu        uint32       // MTU, default 1500
	tunIP      string       // IP address for TUN interface, e.g. "10.0.85.1"
	serverAddr string       // Ghost server IP to exclude from tunnel
	stack      *stack.Stack // gVisor network stack
	tunnel     StreamOpener
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
}

// NewTunDevice creates a new TUN device handler.
// name: TUN interface name (e.g., "ghost0")
// tunIP: IP address for TUN interface (e.g., "10.0.85.1")
// serverAddr: Ghost server IP to exclude from tunnel (prevents routing loop)
func NewTunDevice(name, tunIP, serverAddr string) TunDevice {
	return &tunDevice{
		name:       name,
		mtu:        1500,
		tunIP:      tunIP,
		serverAddr: serverAddr,
	}
}

// Start opens the TUN interface, creates a gVisor userspace network
// stack, and begins intercepting TCP/UDP traffic. Each TCP connection
// is tunneled through Ghost via the provided StreamOpener.
func (t *tunDevice) Start(ctx context.Context, tunnel StreamOpener) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tunnel = tunnel
	t.ctx, t.cancel = context.WithCancel(ctx)

	// Open TUN device — returns raw file descriptor
	fd, err := tun.Open(t.name)
	if err != nil {
		return fmt.Errorf("tun.Open(%s): %w", t.name, err)
	}

	// Create gVisor link endpoint over the TUN fd.
	// EthernetHeader=false because TUN delivers raw IP packets (no L2).
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                []int{fd},
		MTU:                t.mtu,
		EthernetHeader:     false,
		PacketDispatchMode: fdbased.Readv,
	})
	if err != nil {
		return fmt.Errorf("fdbased.New: %w", err)
	}

	// Create gVisor network stack with IPv4/IPv6 + TCP/UDP
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	t.stack = s

	// Create NIC, enable promiscuous + spoofing.
	// Required for transparent proxying — stack must accept packets
	// addressed to any IP, and respond from any IP.
	const nicID = 1
	if tcperr := s.CreateNIC(nicID, ep); tcperr != nil {
		return fmt.Errorf("CreateNIC: %v", tcperr)
	}
	if tcperr := s.SetSpoofing(nicID, true); tcperr != nil {
		return fmt.Errorf("SetSpoofing: %v", tcperr)
	}
	if tcperr := s.SetPromiscuousMode(nicID, true); tcperr != nil {
		return fmt.Errorf("SetPromiscuousMode: %v", tcperr)
	}

	// Default routes — all traffic goes through our NIC
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// TCP buffer tuning for better throughput
	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 212992,
		Max:     4194304,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)

	sndOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 212992,
		Max:     4194304,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)

	// Enable SACK for performance
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Set up TCP and UDP forwarders
	t.setupTCPForwarder(s)
	t.setupUDPForwarder(s)

	// Set up OS routing to direct traffic into TUN
	if err := SetupRouting(t.name, t.tunIP, t.serverAddr); err != nil {
		t.stack.Close()
		t.stack = nil
		return fmt.Errorf("tun: setup routing: %w", err)
	}

	slog.Info("tun device started", "name", t.name, "mtu", t.mtu)
	return nil
}

// Stop tears down the TUN device and gVisor stack.
func (t *tunDevice) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	// Restore OS routing first (while TUN is still up)
	RestoreRouting()

	if t.cancel != nil {
		t.cancel()
	}
	if t.stack != nil {
		t.stack.Close()
		t.stack.Wait()
	}

	slog.Info("tun device stopped", "name", t.name)
	return nil
}

// setupTCPForwarder installs a TCP handler that intercepts all TCP
// connections through the TUN. For each connection:
// 1. gVisor reconstructs the TCP stream (3-way handshake in userspace)
// 2. We get a net.Conn via gonet.NewTCPConn
// 3. We open a Ghost tunnel stream via StreamOpener
// 4. Bidirectional relay between gonet.Conn and tunnel stream
func (t *tunDevice) setupTCPForwarder(s *stack.Stack) {
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dstAddr := id.LocalAddress.String()
		dstPort := id.LocalPort

		var wq waiter.Queue
		ep, tcperr := r.CreateEndpoint(&wq)
		if tcperr != nil {
			slog.Warn("tcp forwarder: CreateEndpoint failed",
				"dst", dstAddr, "port", dstPort, "error", tcperr)
			r.Complete(true) // send RST
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go t.handleTCPConn(conn, dstAddr, dstPort)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
}

// handleTCPConn tunnels a single TCP connection through Ghost.
func (t *tunDevice) handleTCPConn(conn net.Conn, addr string, port uint16) {
	defer conn.Close()

	stream, err := t.tunnel(t.ctx, addr, port)
	if err != nil {
		slog.Debug("tcp tunnel failed", "dst", addr, "port", port, "error", err)
		return
	}
	defer stream.Close()

	slog.Debug("tcp tunnel established",
		"dst", addr, "port", port, "stream_id", stream.ID())

	// Reuse the relay function from server.go (same package)
	relay(conn, stream)
}

// setupUDPForwarder installs a minimal UDP handler.
// For MVP: only forwards DNS (port 53) through the tunnel as TCP.
// Other UDP is logged and dropped.
func (t *tunDevice) setupUDPForwarder(s *stack.Stack) {
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		dstPort := id.LocalPort

		// MVP: only handle DNS (port 53)
		if dstPort != 53 {
			slog.Debug("udp dropped (non-DNS)",
				"dst", id.LocalAddress.String(), "port", dstPort)
			return true // handled (dropped)
		}

		var wq waiter.Queue
		ep, tcperr := r.CreateEndpoint(&wq)
		if tcperr != nil {
			slog.Warn("udp forwarder: CreateEndpoint failed", "error", tcperr)
			return true
		}

		conn := gonet.NewUDPConn(&wq, ep)
		go t.handleDNS(conn, id.LocalAddress.String())
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// handleDNS forwards a DNS UDP query through the Ghost tunnel as TCP.
// DNS-over-TCP is standard (RFC 7766). The query is prefixed with a
// 2-byte length per DNS TCP convention, sent through a tunnel stream,
// and the response is forwarded back to the originating UDP socket.
func (t *tunDevice) handleDNS(conn *gonet.UDPConn, dnsServer string) {
	defer conn.Close()

	// Read UDP DNS query
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 { // minimum DNS header is 12 bytes
		return
	}
	query := buf[:n]

	// Open tunnel stream to DNS server on port 53 (TCP)
	stream, err := t.tunnel(t.ctx, dnsServer, 53)
	if err != nil {
		slog.Debug("dns tunnel failed", "server", dnsServer, "error", err)
		return
	}
	defer stream.Close()

	// Send as DNS-over-TCP: 2-byte length prefix + query
	tcpQuery := make([]byte, 2+len(query))
	tcpQuery[0] = byte(len(query) >> 8)
	tcpQuery[1] = byte(len(query))
	copy(tcpQuery[2:], query)

	if _, err := stream.Write(tcpQuery); err != nil {
		return
	}

	// Read DNS-over-TCP response: 2-byte length prefix + response
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen > 65535 || respLen < 12 {
		return
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return
	}

	// Send response back as UDP
	conn.Write(resp)
}
