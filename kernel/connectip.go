package kernel

import (
	"fmt"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

const (
	// 表示 CONNECT-IP 扩展协议标识。
	ProtocolConnectIP = "connect-ip"
	// 表示会话管理器尚未建立 CONNECT-IP 会话。
	SessionStateIdle = "idle"
)

// 描述建立 CONNECT-IP 会话所需的最小参数。
type ConnectIPOptions struct {
	Authority       string
	Protocol        string
	EnableDatagrams bool
}

// 描述 CONNECT-IP 会话管理器的最小状态快照。
type ConnectIPSnapshot struct {
	State    string
	Protocol string
	Endpoint string
	IPv4     string
	IPv6     string
	Routes   []string
}

// 描述会话建立后分配的地址与路由信息。
type SessionInfo struct {
	IPv4   string
	IPv6   string
	Routes []string
}

// 管理 CONNECT-IP 会话建立阶段的最小状态。
type ConnectIPSessionManager struct {
	state   string
	options ConnectIPOptions
	quic    QUICOptions
	h3      HTTP3Options
	info    SessionInfo
	stats   connectionStats
}

// 基于 HTTP/3 参数生成 CONNECT-IP 会话参数。
func BuildConnectIPOptions(h3 HTTP3Options) ConnectIPOptions {
	return ConnectIPOptions{
		Authority:       h3.Authority,
		Protocol:        ProtocolConnectIP,
		EnableDatagrams: h3.EnableDatagrams,
	}
}

// 创建 CONNECT-IP 会话管理器骨架。
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

// 返回 CONNECT-IP 会话管理器的状态快照。
func (m *ConnectIPSessionManager) Snapshot() ConnectIPSnapshot {
	return ConnectIPSnapshot{
		State:    m.state,
		Protocol: m.options.Protocol,
		Endpoint: m.quic.Endpoint,
		IPv4:     m.info.IPv4,
		IPv6:     m.info.IPv6,
		Routes:   append([]string(nil), m.info.Routes...),
	}
}

// 更新 CONNECT-IP 会话分配的地址与路由。
func (m *ConnectIPSessionManager) UpdateSessionInfo(info SessionInfo) {
	m.info = SessionInfo{
		IPv4:   info.IPv4,
		IPv6:   info.IPv6,
		Routes: append([]string(nil), info.Routes...),
	}
}

// 记录最近一次会话握手时延。
func (m *ConnectIPSessionManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

// 累加会话阶段上行字节数。
func (m *ConnectIPSessionManager) AddTxBytes(n int) {
	m.stats.AddTxBytes(n)
}

// 累加会话阶段下行字节数。
func (m *ConnectIPSessionManager) AddRxBytes(n int) {
	m.stats.AddRxBytes(n)
}

// 返回会话阶段统计快照。
func (m *ConnectIPSessionManager) Stats() types.Stats {
	return m.stats.Snapshot()
}
