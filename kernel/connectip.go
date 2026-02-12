package kernel

import (
	"fmt"

	"github.com/skye-z/amz/config"
)

const (
	// ProtocolConnectIP 表示 CONNECT-IP 扩展协议标识。
	ProtocolConnectIP = "connect-ip"
	// SessionStateIdle 表示会话管理器尚未建立 CONNECT-IP 会话。
	SessionStateIdle = "idle"
)

// ConnectIPOptions 描述建立 CONNECT-IP 会话所需的最小参数。
type ConnectIPOptions struct {
	Authority       string
	Protocol        string
	EnableDatagrams bool
}

// ConnectIPSnapshot 描述 CONNECT-IP 会话管理器的最小状态快照。
type ConnectIPSnapshot struct {
	State    string
	Protocol string
	Endpoint string
}

// ConnectIPSessionManager 管理 CONNECT-IP 会话建立阶段的最小状态。
type ConnectIPSessionManager struct {
	state   string
	options ConnectIPOptions
	quic    QUICOptions
	h3      HTTP3Options
}

// BuildConnectIPOptions 基于 HTTP/3 参数生成 CONNECT-IP 会话参数。
func BuildConnectIPOptions(h3 HTTP3Options) ConnectIPOptions {
	return ConnectIPOptions{
		Authority:       h3.Authority,
		Protocol:        ProtocolConnectIP,
		EnableDatagrams: h3.EnableDatagrams,
	}
}

// NewConnectIPSessionManager 创建 CONNECT-IP 会话管理器骨架。
func NewConnectIPSessionManager(cfg config.KernelConfig) (*ConnectIPSessionManager, error) {
	quic, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	h3 := BuildHTTP3Options(quic)
	return &ConnectIPSessionManager{
		state:   SessionStateIdle,
		options: BuildConnectIPOptions(h3),
		quic:    quic,
		h3:      h3,
	}, nil
}

// Snapshot 返回 CONNECT-IP 会话管理器的状态快照。
func (m *ConnectIPSessionManager) Snapshot() ConnectIPSnapshot {
	return ConnectIPSnapshot{
		State:    m.state,
		Protocol: m.options.Protocol,
		Endpoint: m.quic.Endpoint,
	}
}
