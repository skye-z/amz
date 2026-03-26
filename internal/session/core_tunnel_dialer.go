package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	amzconfig "github.com/skye-z/amz/internal/config"
	internaltun "github.com/skye-z/amz/internal/tun"
)

// CoreTunnelDialer 在实际拨号前确保 QUIC/H3 与 CONNECT-IP 核心会话已就绪。
// 当前阶段它负责“核心会话编排 + TUN/PacketRelay 启动 + 共享拨号抽象”。
type CoreTunnelDialer struct {
	connection *ConnectionManager
	session    *ConnectIPSessionManager
	delegate   HTTPStreamDialer
	streamMgr  *ConnectStreamManager

	mu              sync.Mutex
	packetIO        *PacketIO
	assemblyFactory func(opts internaltun.AssembleOptions) (*internaltun.Assembly, error)
	provider        internaltun.PlatformProvider
	adapter         internaltun.Adapter
	packetRelay     func(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error

	assembly    *internaltun.Assembly
	relayCancel context.CancelCauseFunc
	relayDone   chan error
	relayErr    error
}

// 创建一个会在拨号前确保核心会话已建立的共享 dialer。
func NewCoreTunnelDialer(connection *ConnectionManager, session *ConnectIPSessionManager, delegate HTTPStreamDialer) (*CoreTunnelDialer, error) {
	if connection == nil {
		return nil, fmt.Errorf("connection manager is required")
	}
	if session == nil {
		return nil, fmt.Errorf("connect-ip session manager is required")
	}
	if delegate == nil {
		delegate = &net.Dialer{}
	}
	streamMgr, err := NewConnectStreamManager(connection.cfg)
	if err != nil {
		return nil, fmt.Errorf("connect stream manager: %w", err)
	}
	return &CoreTunnelDialer{
		connection:      connection,
		session:         session,
		delegate:        delegate,
		streamMgr:       streamMgr,
		packetIO:        NewPacketIO(connection.cfg.MTU),
		assemblyFactory: internaltun.Assemble,
	}, nil
}

// Prepare 在对外暴露代理前预热并绑定核心会话与 stream manager。
func (d *CoreTunnelDialer) Prepare(ctx context.Context) error {
	return d.ensureReady(ctx)
}

// StreamManager 返回与当前核心会话绑定的 CONNECT stream manager。
func (d *CoreTunnelDialer) StreamManager() *ConnectStreamManager {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.streamMgr
}

// SessionInfo 返回当前核心 CONNECT-IP 会话快照，供上层用户态数据面复用。
func (d *CoreTunnelDialer) SessionInfo() SessionInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == nil {
		return SessionInfo{}
	}
	snapshot := d.session.Snapshot()
	return SessionInfo{
		IPv4:   snapshot.IPv4,
		IPv6:   snapshot.IPv6,
		Routes: append([]string(nil), snapshot.Routes...),
	}
}

// PacketEndpoint 返回当前核心 CONNECT-IP 会话的数据面端点。
func (d *CoreTunnelDialer) PacketEndpoint() PacketRelayEndpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == nil {
		return nil
	}
	return d.session.PacketEndpoint()
}

// 在共享 dialer 拨号前建立并复用核心会话。
func (d *CoreTunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.ensureReady(ctx); err != nil {
		return nil, err
	}
	return d.delegate.DialContext(ctx, network, address)
}

func (d *CoreTunnelDialer) ensureReady(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.relayErr != nil {
		return d.relayErr
	}
	if err := d.connection.Connect(ctx); err != nil {
		return fmt.Errorf("ensure quic/http3 ready: %w", err)
	}
	h3conn := d.connection.HTTP3Conn()
	if d.streamMgr != nil {
		d.streamMgr.BindHTTP3Conn(h3conn)
		d.streamMgr.SetReady()
	}
	d.session.BindHTTP3Conn(h3conn)
	if err := d.session.Open(ctx); err != nil {
		return fmt.Errorf("ensure connect-ip ready: %w", err)
	}
	if d.connection.cfg.Mode != amzconfig.ModeTUN {
		return nil
	}
	if d.assembly == nil {
		assembly, err := d.assemblyFactory(d.buildAssembleOptions())
		if err != nil {
			return fmt.Errorf("ensure tun assembly ready: %w", err)
		}
		relayCtx, cancel := context.WithCancelCause(context.Background())
		done := make(chan error, 1)
		d.assembly = assembly
		d.relayCancel = cancel
		d.relayDone = done
		packetRelay := d.packetRelay
		if packetRelay == nil {
			packetRelay = d.packetIO.Relay
		}
		go func(dev TUNDevice, endpoint PacketRelayEndpoint) {
			err := packetRelay(relayCtx, dev, endpoint)
			if err != nil && !errors.Is(err, context.Canceled) {
				d.mu.Lock()
				if d.relayErr == nil {
					d.relayErr = err
				}
				d.mu.Unlock()
			}
			done <- err
		}(d.assembly.Device, d.session.PacketEndpoint())
	}
	return nil
}

func (d *CoreTunnelDialer) buildAssembleOptions() internaltun.AssembleOptions {
	cfg := d.connection.cfg
	cfg.FillDefaults()

	deviceName := strings.TrimSpace(cfg.TUN.Name)
	if deviceName == "" {
		deviceName = "igara0"
	}

	snapshot := d.session.Snapshot()
	addresses := make([]internaltun.Address, 0, 2)
	routes := make([]string, 0, 2)
	if snapshot.IPv4 != "" {
		addresses = append(addresses, internaltun.Address{CIDR: snapshot.IPv4})
		routes = append(routes, "0.0.0.0/0")
	}
	if snapshot.IPv6 != "" {
		addresses = append(addresses, internaltun.Address{CIDR: snapshot.IPv6})
		routes = append(routes, "::/0")
	}

	return internaltun.AssembleOptions{
		Device: internaltun.DeviceConfig{
			Name: deviceName,
			MTU:  cfg.MTU,
		},
		Config: internaltun.Config{
			Device: internaltun.DeviceConfig{
				Name: deviceName,
				MTU:  cfg.MTU,
			},
			Addresses: addresses,
		},
		Routes: internaltun.RoutePlan{
			Mode:           resolveInternalRouteMode(routes),
			Routes:         routes,
			EndpointRoutes: buildEndpointRoutes(cfg.Endpoint),
		},
		Provider: d.provider,
		Adapter:  d.adapter,
	}
}

func resolveInternalRouteMode(routes []string) internaltun.RouteMode {
	if len(routes) == 2 {
		return internaltun.RouteModeGlobal
	}
	return internaltun.RouteModeSplit
}

func buildEndpointRoutes(endpoint string) []string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		host = strings.TrimSpace(endpoint)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return []string{"0.0.0.0/32"}
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		addr := netip.AddrFrom4([4]byte(ipv4))
		return []string{netip.PrefixFrom(addr, 32).String()}
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return []string{"0.0.0.0/32"}
	}
	return []string{netip.PrefixFrom(addr, 128).String()}
}

// 关闭核心会话拨号器持有的核心资源。
func (d *CoreTunnelDialer) Close() error {
	d.mu.Lock()
	cancel := d.relayCancel
	done := d.relayDone
	assembly := d.assembly
	d.relayCancel = nil
	d.relayDone = nil
	d.assembly = nil
	d.relayErr = nil
	d.mu.Unlock()

	if cancel != nil {
		cancel(context.Canceled)
	}
	if done != nil {
		<-done
	}
	var closeErr error
	if d.streamMgr != nil {
		if err := d.streamMgr.Close(); err != nil {
			closeErr = err
		}
	}
	if assembly != nil {
		if err := assembly.Close(); err != nil {
			closeErr = err
		}
	}
	if err := d.session.Close(); err != nil && closeErr == nil {
		closeErr = err
	}
	if err := d.connection.Close(); err != nil && closeErr == nil {
		closeErr = err
	}
	return closeErr
}
