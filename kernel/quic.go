package kernel

import (
	"fmt"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

const (
	// 表示连接管理器尚未建立会话。
	ConnStateIdle = "idle"
	// 表示连接管理器正在准备建立会话。
	ConnStateConnecting = "connecting"
	// 表示连接管理器已具备传输参数。
	ConnStateReady = "ready"
)

// 描述建立 QUIC 会话所需的最小参数。
type QUICOptions struct {
	Endpoint             string
	ServerName           string
	EnableDatagrams      bool
	Keepalive            string
	CongestionControl    string
	ConnectionParameters map[string]string
}

// 描述建立 HTTP/3 客户端连接所需的最小参数。
type HTTP3Options struct {
	Authority            string
	EnableDatagrams      bool
	ConnectionParameters map[string]string
}

// 描述连接管理器当前的最小状态快照。
type ConnectionSnapshot struct {
	State    string
	Endpoint string
	SNI      string
}

// 持有连接管理阶段的基础配置与状态。
type ConnectionManager struct {
	cfg   config.KernelConfig
	state string
	quic  QUICOptions
	h3    HTTP3Options
	stats connectionStats
}

// 将配置映射为最小 QUIC 连接参数。
func BuildQUICOptions(cfg config.KernelConfig) (QUICOptions, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return QUICOptions{}, err
	}
	return QUICOptions{
		Endpoint:             clone.Endpoint,
		ServerName:           clone.SNI,
		EnableDatagrams:      true,
		Keepalive:            clone.Keepalive.String(),
		CongestionControl:    clone.QUIC.CongestionControl,
		ConnectionParameters: cloneConnectionParameters(clone.QUIC.ConnectionParameters),
	}, nil
}

// 基于 QUIC 参数生成 HTTP/3 连接参数。
func BuildHTTP3Options(quic QUICOptions) HTTP3Options {
	return HTTP3Options{
		Authority:            quic.Endpoint,
		EnableDatagrams:      quic.EnableDatagrams,
		ConnectionParameters: cloneConnectionParameters(quic.ConnectionParameters),
	}
}

// 复制连接参数映射，避免不同阶段共享可变状态。
func cloneConnectionParameters(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

// 创建最小连接管理器骨架。
func NewConnectionManager(cfg config.KernelConfig) (*ConnectionManager, error) {
	quic, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	return &ConnectionManager{
		cfg:   cfg,
		state: ConnStateIdle,
		quic:  quic,
		h3:    BuildHTTP3Options(quic),
	}, nil
}

// 返回当前连接管理器状态快照。
func (m *ConnectionManager) Snapshot() ConnectionSnapshot {
	return ConnectionSnapshot{
		State:    m.state,
		Endpoint: m.quic.Endpoint,
		SNI:      m.quic.ServerName,
	}
}

// 记录最近一次连接握手时延。
func (m *ConnectionManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

// 累加连接阶段上行字节数。
func (m *ConnectionManager) AddTxBytes(n int) {
	m.stats.AddTxBytes(n)
}

// 累加连接阶段下行字节数。
func (m *ConnectionManager) AddRxBytes(n int) {
	m.stats.AddRxBytes(n)
}

// 返回连接阶段统计快照。
func (m *ConnectionManager) Stats() types.Stats {
	return m.stats.Snapshot()
}
