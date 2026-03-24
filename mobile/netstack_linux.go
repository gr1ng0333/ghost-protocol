//go:build linux

package ghost

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"ghost/internal/proxy"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// setupNetstack creates a gVisor userspace network stack from a raw TUN file
// descriptor. TCP connections are tunneled through Ghost via the opener.
// DNS (UDP 53) is converted to TCP. Other UDP is dropped.
// Returns a stop function to tear down the stack.
func setupNetstack(ctx context.Context, tunFile *os.File, mtu uint32, opener proxy.StreamOpener) (stop func(), err error) {
	fd := int(tunFile.Fd())

	ep, err := fdbased.New(&fdbased.Options{
		FDs:                []int{fd},
		MTU:                mtu,
		EthernetHeader:     false,
		PacketDispatchMode: fdbased.Readv,
	})
	if err != nil {
		return nil, fmt.Errorf("fdbased.New: %w", err)
	}

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

	const nicID = 1
	if tcperr := s.CreateNIC(nicID, ep); tcperr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcperr)
	}
	if tcperr := s.SetSpoofing(nicID, true); tcperr != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", tcperr)
	}
	if tcperr := s.SetPromiscuousMode(nicID, true); tcperr != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", tcperr)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// TCP buffer tuning
	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 212992, Max: 4194304}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)
	sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 212992, Max: 4194304}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// TCP forwarder
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dstAddr := id.LocalAddress.String()
		dstPort := id.LocalPort

		var wq waiter.Queue
		ep, tcperr := r.CreateEndpoint(&wq)
		if tcperr != nil {
			slog.Warn("tcp forwarder: CreateEndpoint failed",
				"dst", dstAddr, "port", dstPort, "error", tcperr)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go handleTCPConn(ctx, conn, dstAddr, dstPort, opener)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP forwarder — DNS only
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		dstPort := id.LocalPort

		if dstPort != 53 {
			slog.Debug("udp dropped (non-DNS)",
				"dst", id.LocalAddress.String(), "port", dstPort)
			return true
		}

		var wq waiter.Queue
		ep, tcperr := r.CreateEndpoint(&wq)
		if tcperr != nil {
			slog.Warn("udp forwarder: CreateEndpoint failed", "error", tcperr)
			return true
		}

		conn := gonet.NewUDPConn(&wq, ep)
		go handleDNS(ctx, conn, id.LocalAddress.String(), opener)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	slog.Info("gVisor netstack started", "mtu", mtu)

	stop = func() {
		s.Close()
		s.Wait()
		slog.Info("gVisor netstack stopped")
	}
	return stop, nil
}

func handleTCPConn(ctx context.Context, conn net.Conn, addr string, port uint16, opener proxy.StreamOpener) {
	defer conn.Close()

	stream, err := opener(ctx, addr, port)
	if err != nil {
		slog.Debug("tcp tunnel failed", "dst", addr, "port", port, "error", err)
		return
	}
	defer stream.Close()

	slog.Debug("tcp tunnel established", "dst", addr, "port", port, "stream_id", stream.ID())

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst io.Writer, src io.Reader, close func()) {
		defer wg.Done()
		io.Copy(dst, src)
		close()
	}
	go cp(conn, stream, func() { conn.Close() })
	go cp(stream, conn, func() { stream.Close() })
	wg.Wait()
}
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return
	}
	query := buf[:n]

	stream, err := opener(ctx, dnsServer, 53)
	if err != nil {
		slog.Debug("dns tunnel failed", "server", dnsServer, "error", err)
		return
	}
	defer stream.Close()

	// DNS-over-TCP: 2-byte length prefix + query
	tcpQuery := make([]byte, 2+len(query))
	tcpQuery[0] = byte(len(query) >> 8)
	tcpQuery[1] = byte(len(query))
	copy(tcpQuery[2:], query)

	if _, err := stream.Write(tcpQuery); err != nil {
		return
	}

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

	conn.Write(resp)
}


