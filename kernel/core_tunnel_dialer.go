package kernel

import (
	"context"
	"fmt"
	"net"
)

// CoreTunnelDialer 在实际拨号前确保 QUIC/H3 与 CONNECT-IP 核心会话已就绪。
// 当前阶段它负责“核心会话编排 + 共享拨号抽象”，后续可替换为真正的 tunnel-backed stream dialer。
type CoreTunnelDialer struct {
	connection *ConnectionManager
	session    *ConnectIPSessionManager
	delegate   HTTPStreamDialer
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
	return &CoreTunnelDialer{
		connection: connection,
		session:    session,
		delegate:   delegate,
	}, nil
}

// 在共享 dialer 拨号前建立并复用核心会话。
func (d *CoreTunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.ensureReady(ctx); err != nil {
		return nil, err
	}
	return d.delegate.DialContext(ctx, network, address)
}

func (d *CoreTunnelDialer) ensureReady(ctx context.Context) error {
	if err := d.connection.Connect(ctx); err != nil {
		return fmt.Errorf("ensure quic/http3 ready: %w", err)
	}
	d.session.BindHTTP3Conn(d.connection.HTTP3Conn())
	if err := d.session.Open(ctx); err != nil {
		return fmt.Errorf("ensure connect-ip ready: %w", err)
	}
	return nil
}
