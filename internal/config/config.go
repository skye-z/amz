package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	StateIdle    = "idle"
	StateRunning = "running"
	StateStopped = "stopped"
)

const (
	EventTypeStateChanged = "state_changed"
)

var (
	ErrInvalidConfig   = errors.New("invalid config")
	ErrUnsupportedMode = errors.New("unsupported mode")
	ErrNotImplemented  = errors.New("not implemented")
)

type Event struct {
	Type      string
	State     string
	Message   string
	Timestamp time.Time
}

type EventHandler func(Event)

type Stats struct {
	StartCount       int
	StopCount        int
	ReconnectCount   int
	TxBytes          int
	RxBytes          int
	HandshakeLatency time.Duration
}

type LifecycleStats struct {
	Starts     int `json:"starts"`
	Stops      int `json:"stops"`
	Reconnects int `json:"reconnects"`
}

type TrafficStats struct {
	TxBytes    int `json:"tx_bytes"`
	RxBytes    int `json:"rx_bytes"`
	TotalBytes int `json:"total_bytes"`
}

type TimingStats struct {
	HandshakeLatencyMillis int64 `json:"handshake_latency_ms"`
}

type StructuredStats struct {
	Lifecycle LifecycleStats `json:"lifecycle"`
	Traffic   TrafficStats   `json:"traffic"`
	Timing    TimingStats    `json:"timing"`
}

func (s Stats) Structured() StructuredStats {
	return StructuredStats{
		Lifecycle: LifecycleStats{Starts: s.StartCount, Stops: s.StopCount, Reconnects: s.ReconnectCount},
		Traffic:   TrafficStats{TxBytes: s.TxBytes, RxBytes: s.RxBytes, TotalBytes: s.TxBytes + s.RxBytes},
		Timing:    TimingStats{HandshakeLatencyMillis: s.HandshakeLatency.Milliseconds()},
	}
}

func (s Stats) Fields() map[string]any {
	structured := s.Structured()
	return map[string]any{
		"lifecycle.starts":              structured.Lifecycle.Starts,
		"lifecycle.stops":               structured.Lifecycle.Stops,
		"lifecycle.reconnects":          structured.Lifecycle.Reconnects,
		"traffic.tx_bytes":              structured.Traffic.TxBytes,
		"traffic.rx_bytes":              structured.Traffic.RxBytes,
		"traffic.total_bytes":           structured.Traffic.TotalBytes,
		"timing.handshake_latency_ms":   structured.Timing.HandshakeLatencyMillis,
		"timing.handshake_latency_text": s.HandshakeLatency.String(),
	}
}

type Tunnel interface {
	Start(context.Context) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() Stats
}

type ConnectionStats struct {
	mu    sync.Mutex
	stats Stats
}

func (s *ConnectionStats) RecordHandshakeLatency(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.HandshakeLatency = latency
}

func (s *ConnectionStats) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TxBytes += n
}

func (s *ConnectionStats) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.RxBytes += n
}

func (s *ConnectionStats) AddReconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ReconnectCount++
}

func (s *ConnectionStats) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// 描述内核可选使用的最小日志接口。
type Logger interface {
	Printf(format string, args ...any)
}

const (
	// 默认端点指向 Cloudflare MASQUE 服务。
	DefaultEndpoint = "162.159.198.1:443"
	// 默认 SNI 与当前真实可用的 WARP Proxy Mode 行为保持一致。
	DefaultSNI = "warp.cloudflare.com"
	// 默认 MTU 兼顾通用平台与隧道开销。
	DefaultMTU = 1280
)

const (
	// 默认保活间隔避免空闲连接过早回收。
	DefaultKeepalive = 30 * time.Second
	// 默认握手超时用于限制启动阻塞时间。
	DefaultConnectTimeout = 10 * time.Second
)

const (
	// 提供最小 SOCKS5 监听地址。
	DefaultSOCKSListenAddress = "127.0.0.1:1080"
	// 提供最小 HTTP 代理监听地址。
	DefaultHTTPListenAddress = "127.0.0.1:8080"
)

// 描述 TUN 模式的最小参数。
type TUNConfig struct {
	Name string
}

// 描述 SOCKS 模式的最小参数。
type SOCKSConfig struct {
	ListenAddress string
	Username      string
	Password      string
	EnableUDP     bool
}

// 描述 HTTP 模式的最小参数。
type HTTPConfig struct {
	ListenAddress   string
	UpstreamAddress string
}

// 描述 QUIC 与 HTTP/3 连接管理的扩展预留参数。
type QUICConfig struct {
	CongestionControl    string
	ConnectionParameters map[string]string
}

type TLSConfig struct {
	ClientPrivateKey  string
	ClientCertificate string
	PeerPublicKey     string
	EndpointV4        string
	EndpointV6        string
	ClientID          string
}

const (
	// 表示通过系统 TUN 暴露隧道。
	ModeTUN = "tun"
	// 表示通过 SOCKS5 暴露隧道。
	ModeSOCKS = "socks"
	// 表示通过 HTTP 代理暴露隧道。
	ModeHTTP = "http"
)

// 描述内核启动所需的最小参数集合。
type KernelConfig struct {
	Endpoint       string
	SNI            string
	MTU            int
	Mode           string
	Keepalive      time.Duration
	ConnectTimeout time.Duration
	QUIC           QUICConfig
	TLS            TLSConfig
	Logger         Logger
	TUN            TUNConfig
	SOCKS          SOCKSConfig
	HTTP           HTTPConfig
}

// 为基础阶段补齐最小可运行默认值。
func (c *KernelConfig) FillDefaults() {
	if strings.TrimSpace(c.Endpoint) == "" {
		c.Endpoint = DefaultEndpoint
	}
	if strings.TrimSpace(c.SNI) == "" {
		c.SNI = DefaultSNI
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if strings.TrimSpace(c.Mode) == "" {
		c.Mode = ModeTUN
	}
	if c.Keepalive == 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	switch c.Mode {
	case ModeTUN:
		if strings.TrimSpace(c.TUN.Name) == "" {
			c.TUN.Name = "igara0"
		}
	case ModeSOCKS:
		if strings.TrimSpace(c.SOCKS.ListenAddress) == "" {
			c.SOCKS.ListenAddress = DefaultSOCKSListenAddress
		}
	case ModeHTTP:
		if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
			c.HTTP.ListenAddress = DefaultHTTPListenAddress
		}
	}
}

// 检查配置是否满足最小骨架约束。
func (c KernelConfig) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("%w: endpoint is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.SNI) == "" {
		return fmt.Errorf("%w: sni is required", ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", ErrInvalidConfig)
	}
	if c.Keepalive < 0 {
		return fmt.Errorf("%w: keepalive must be positive", ErrInvalidConfig)
	}
	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("%w: connect timeout must be positive", ErrInvalidConfig)
	}
	switch c.Mode {
	case ModeTUN:
		if strings.TrimSpace(c.TUN.Name) == "" {
			return fmt.Errorf("%w: tun name is required", ErrInvalidConfig)
		}
		return nil
	case ModeSOCKS:
		if strings.TrimSpace(c.SOCKS.ListenAddress) == "" {
			return fmt.Errorf("%w: socks listen address is required", ErrInvalidConfig)
		}
		return nil
	case ModeHTTP:
		if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
			return fmt.Errorf("%w: http listen address is required", ErrInvalidConfig)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMode, c.Mode)
	}
}
