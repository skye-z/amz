package kernel

import (
	"fmt"

	"github.com/skye-z/amz/config"
)

const (
	// ConnStateIdle 表示连接管理器尚未建立会话。
	ConnStateIdle = "idle"
	// ConnStateConnecting 表示连接管理器正在准备建立会话。
	ConnStateConnecting = "connecting"
	// ConnStateReady 表示连接管理器已具备传输参数。
	ConnStateReady = "ready"
)

// QUICOptions 描述建立 QUIC 会话所需的最小参数。
type QUICOptions struct {
	Endpoint        string
	ServerName      string
	EnableDatagrams bool
	Keepalive       string
}

// HTTP3Options 描述建立 HTTP/3 客户端连接所需的最小参数。
type HTTP3Options struct {
	Authority       string
	EnableDatagrams bool
}

// ConnectionSnapshot 描述连接管理器当前的最小状态快照。
type ConnectionSnapshot struct {
	State    string
	Endpoint string
	SNI      string
}

// ConnectionManager 持有连接管理阶段的基础配置与状态。
type ConnectionManager struct {
	cfg   config.KernelConfig
	state string
	quic  QUICOptions
	h3    HTTP3Options
}

// BuildQUICOptions 将配置映射为最小 QUIC 连接参数。
func BuildQUICOptions(cfg config.KernelConfig) (QUICOptions, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return QUICOptions{}, err
	}
	return QUICOptions{
		Endpoint:        clone.Endpoint,
		ServerName:      clone.SNI,
		EnableDatagrams: true,
		Keepalive:       clone.Keepalive.String(),
	}, nil
}

// BuildHTTP3Options 基于 QUIC 参数生成 HTTP/3 连接参数。
func BuildHTTP3Options(quic QUICOptions) HTTP3Options {
	return HTTP3Options{
		Authority:       quic.Endpoint,
		EnableDatagrams: quic.EnableDatagrams,
	}
}

// NewConnectionManager 创建最小连接管理器骨架。
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

// Snapshot 返回当前连接管理器状态快照。
func (m *ConnectionManager) Snapshot() ConnectionSnapshot {
	return ConnectionSnapshot{
		State:    m.state,
		Endpoint: m.quic.Endpoint,
		SNI:      m.quic.ServerName,
	}
}
