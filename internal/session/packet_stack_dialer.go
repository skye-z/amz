package session

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	gonet "github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	ipv4 "github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	ipv6 "github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	gicmp "github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	gtcp "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	gudp "github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

const packetStackNICID tcpip.NICID = 1

type packetStackBootstrap interface {
	Prepare(context.Context) error
	SessionInfo() SessionInfo
	PacketEndpoint() PacketRelayEndpoint
	Close() error
}

type PacketStackDialer struct {
	mu        sync.Mutex
	bootstrap packetStackBootstrap
	stack     *stack.Stack
	endpoint  *packetStackLinkEndpoint
}

func NewPacketStackDialer(bootstrap packetStackBootstrap) (*PacketStackDialer, error) {
	if bootstrap == nil {
		return nil, fmt.Errorf("packet stack bootstrap is required")
	}
	return &PacketStackDialer{bootstrap: bootstrap}, nil
}

func (d *PacketStackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("packet stack dialer only supports tcp, got %q", network)
	}
	stackValue, local4, local6, err := d.ensureStack(ctx)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("parse packet target %q: %w", address, err)
	}
	target, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return nil, fmt.Errorf("packet stack dialer requires IP literal target: %w", err)
	}
	portValue, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("parse packet target port %q: %w", port, err)
	}

	if target.Is4() {
		if !local4.IsValid() {
			return nil, fmt.Errorf("packet stack local ipv4 is unavailable")
		}
		return gonet.DialTCPWithBind(ctx, stackValue,
			tcpip.FullAddress{NIC: packetStackNICID, Addr: tcpip.AddrFrom4(local4.As4())},
			tcpip.FullAddress{NIC: packetStackNICID, Addr: tcpip.AddrFrom4(target.As4()), Port: uint16(portValue)},
			ipv4.ProtocolNumber,
		)
	}
	if !local6.IsValid() {
		return nil, fmt.Errorf("packet stack local ipv6 is unavailable")
	}
	return gonet.DialTCPWithBind(ctx, stackValue,
		tcpip.FullAddress{NIC: packetStackNICID, Addr: tcpip.AddrFrom16(local6.As16())},
		tcpip.FullAddress{NIC: packetStackNICID, Addr: tcpip.AddrFrom16(target.As16()), Port: uint16(portValue)},
		ipv6.ProtocolNumber,
	)
}

func (d *PacketStackDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stack = nil
	d.endpoint = nil
	if d.bootstrap == nil {
		return nil
	}
	return d.bootstrap.Close()
}

func (d *PacketStackDialer) ensureStack(ctx context.Context) (*stack.Stack, netip.Addr, netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.stack != nil {
		return d.stack, d.endpoint.local4, d.endpoint.local6, nil
	}
	if err := d.bootstrap.Prepare(ctx); err != nil {
		return nil, netip.Addr{}, netip.Addr{}, err
	}
	sessionInfo := d.bootstrap.SessionInfo()
	packetEndpoint := d.bootstrap.PacketEndpoint()
	if packetEndpoint == nil {
		return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("packet endpoint is unavailable")
	}

	local4, local6, err := parsePacketLocalAddrs(sessionInfo)
	if err != nil {
		return nil, netip.Addr{}, netip.Addr{}, err
	}
	linkEndpoint := &packetStackLinkEndpoint{
		ctx:      context.Background(),
		endpoint: packetEndpoint,
		mtu:      1280,
		local4:   local4,
		local6:   local6,
	}
	stackValue := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol, gudp.NewProtocol, gicmp.NewProtocol4, gicmp.NewProtocol6},
	})
	if err := stackValue.CreateNIC(packetStackNICID, linkEndpoint); err != nil {
		return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("create packet nic: %v", err)
	}
	if err := stackValue.SetSpoofing(packetStackNICID, true); err != nil {
		return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("set packet nic spoofing: %v", err)
	}
	if err := stackValue.SetPromiscuousMode(packetStackNICID, true); err != nil {
		return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("set packet nic promiscuous: %v", err)
	}
	routes := make([]tcpip.Route, 0, 2)
	if local4.IsValid() {
		if err := stackValue.AddProtocolAddress(packetStackNICID, tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(local4.As4()),
				PrefixLen: 32,
			},
		}, stack.AddressProperties{}); err != nil {
			return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("add packet ipv4 address: %v", err)
		}
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: packetStackNICID})
	}
	if local6.IsValid() {
		if err := stackValue.AddProtocolAddress(packetStackNICID, tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(local6.As16()),
				PrefixLen: 128,
			},
		}, stack.AddressProperties{}); err != nil {
			return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("add packet ipv6 address: %v", err)
		}
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: packetStackNICID})
	}
	stackValue.SetRouteTable(routes)

	d.endpoint = linkEndpoint
	d.stack = stackValue
	return stackValue, local4, local6, nil
}

func parsePacketLocalAddrs(info SessionInfo) (netip.Addr, netip.Addr, error) {
	var local4 netip.Addr
	var local6 netip.Addr
	if trimmed := strings.TrimSpace(info.IPv4); trimmed != "" {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("parse packet local ipv4 %q: %w", trimmed, err)
		}
		local4 = prefix.Addr()
	}
	if trimmed := strings.TrimSpace(info.IPv6); trimmed != "" {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("parse packet local ipv6 %q: %w", trimmed, err)
		}
		local6 = prefix.Addr()
	}
	if !local4.IsValid() && !local6.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("packet stack local address is unavailable")
	}
	return local4, local6, nil
}

type packetStackLinkEndpoint struct {
	ctx        context.Context
	endpoint   PacketRelayEndpoint
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	local4     netip.Addr
	local6     netip.Addr
}

func (e *packetStackLinkEndpoint) MTU() uint32                           { return e.mtu }
func (e *packetStackLinkEndpoint) SetMTU(mtu uint32)                     {}
func (e *packetStackLinkEndpoint) MaxHeaderLength() uint16               { return 0 }
func (e *packetStackLinkEndpoint) LinkAddress() tcpip.LinkAddress        { return "" }
func (e *packetStackLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {}
func (e *packetStackLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (e *packetStackLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	if dispatcher != nil {
		go e.readLoop()
	}
}
func (e *packetStackLinkEndpoint) IsAttached() bool { return e.dispatcher != nil }
func (e *packetStackLinkEndpoint) Wait()            {}
func (e *packetStackLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}
func (e *packetStackLinkEndpoint) AddHeader(pkt *stack.PacketBuffer) {}
func (e *packetStackLinkEndpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	return true
}
func (e *packetStackLinkEndpoint) Close()                  {}
func (e *packetStackLinkEndpoint) SetOnCloseAction(func()) {}

func (e *packetStackLinkEndpoint) readLoop() {
	for {
		buf := make([]byte, maxPacketBufferSize)
		n, err := e.endpoint.ReadPacket(e.ctx, buf)
		if err != nil {
			return
		}
		if n <= 0 || e.dispatcher == nil {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		var protocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			protocol = ipv4.ProtocolNumber
		case header.IPv6Version:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(packet),
			IsForwardedPacket: true,
		})
		e.dispatcher.DeliverNetworkPacket(protocol, pkt)
		pkt.DecRef()
	}
}

func (e *packetStackLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	for _, pkt := range list.AsSlice() {
		var packet []byte
		for _, chunk := range pkt.AsSlices() {
			packet = append(packet, chunk...)
		}
		if _, err := e.endpoint.WritePacket(e.ctx, packet); err != nil {
			return written, &tcpip.ErrAborted{}
		}
		written++
	}
	return written, nil
}
