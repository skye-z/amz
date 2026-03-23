package kernel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

var errProxyAlreadyStopped = errors.New("proxy manager already stopped")

// 管理 SOCKS5 模式的最小监听骨架。
type SOCKSManager struct {
	mu            sync.Mutex
	cfg           config.KernelConfig
	state         string
	stats         types.Stats
	listen        string
	listener      net.Listener
	udpPacketConn net.PacketConn
	runCancel     context.CancelFunc
	runWG         sync.WaitGroup
	udpRelay      UDPAssociateRelay
	associations  map[string]*udpAssociation
}

// 描述 SOCKS5 管理器的最小配置快照。
type SOCKSSnapshot struct {
	ListenAddress string
	Username      string
	EnableUDP     bool
}

// 管理 HTTP 代理模式的最小监听骨架。
type HTTPProxyManager struct {
	mu        sync.Mutex
	cfg       config.KernelConfig
	state     string
	stats     types.Stats
	listen    string
	listener  net.Listener
	server    *http.Server
	runWG     sync.WaitGroup
	dialer    HTTPStreamDialer
	transport http.RoundTripper
}

// 描述 HTTP 代理管理器的最小配置快照。
type HTTPSnapshot struct {
	ListenAddress        string
	ReuseTunnelLifecycle bool
}

// 创建 SOCKS5 模式的最小管理器。
func NewSOCKSManager(cfg *config.KernelConfig) (*SOCKSManager, error) {
	clone, err := normalizeProxyConfig(cfg, config.ModeSOCKS, true)
	if err != nil {
		return nil, err
	}
	return &SOCKSManager{
		cfg:    clone,
		state:  types.StateIdle,
		listen: clone.SOCKS.ListenAddress,
	}, nil
}

// 创建 HTTP 代理模式的最小管理器。
func NewHTTPProxyManager(cfg config.KernelConfig) (*HTTPProxyManager, error) {
	clone, err := normalizeProxyConfig(&cfg, config.ModeHTTP, false)
	if err != nil {
		return nil, err
	}
	return &HTTPProxyManager{
		cfg:    clone,
		state:  types.StateIdle,
		listen: clone.HTTP.ListenAddress,
	}, nil
}

// 返回 SOCKS5 管理器的监听地址快照。
func (m *SOCKSManager) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listen
}

// 复用停止流程，便于上层统一回收。
func (m *SOCKSManager) Close() error {
	return m.Stop(context.Background())
}

// 返回 SOCKS5 管理器当前状态。
func (m *SOCKSManager) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// 返回 SOCKS5 管理器统计快照。
func (m *SOCKSManager) Stats() types.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// 返回 SOCKS5 管理器的配置快照。
func (m *SOCKSManager) Snapshot() SOCKSSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SOCKSSnapshot{
		ListenAddress: m.listen,
		Username:      m.cfg.SOCKS.Username,
		EnableUDP:     m.cfg.SOCKS.EnableUDP,
	}
}

// 记录最近一次握手时延，便于轻量模式暴露最小资源快照。
func (m *SOCKSManager) RecordHandshakeLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.HandshakeLatency = latency
}

// 累加上行字节数，忽略非正数输入。
func (m *SOCKSManager) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.TxBytes += n
}

// 累加下行字节数，忽略非正数输入。
func (m *SOCKSManager) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RxBytes += n
}

// 累加重连次数，便于上层观测轻量模式稳定性。
func (m *SOCKSManager) AddReconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.ReconnectCount++
}

// 返回 HTTP 代理管理器的监听地址快照。
func (m *HTTPProxyManager) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listen
}

// 复用停止流程，便于上层统一回收。
func (m *HTTPProxyManager) Close() error {
	return m.Stop(context.Background())
}

// 返回 HTTP 代理管理器当前状态。
func (m *HTTPProxyManager) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// 返回 HTTP 代理管理器统计快照。
func (m *HTTPProxyManager) Stats() types.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// 返回 HTTP 代理管理器的配置快照。
func (m *HTTPProxyManager) Snapshot() HTTPSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return HTTPSnapshot{
		ListenAddress:        m.listen,
		ReuseTunnelLifecycle: true,
	}
}

// 记录最近一次握手时延，便于轻量模式暴露最小资源快照。
func (m *HTTPProxyManager) RecordHandshakeLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.HandshakeLatency = latency
}

// 累加上行字节数，忽略非正数输入。
func (m *HTTPProxyManager) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.TxBytes += n
}

// 累加下行字节数，忽略非正数输入。
func (m *HTTPProxyManager) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RxBytes += n
}

// 累加重连次数，便于上层观测轻量模式稳定性。
func (m *HTTPProxyManager) AddReconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.ReconnectCount++
}

// 输出 SOCKS5 生命周期相关的最小日志，未注入时保持静默。
func (m *SOCKSManager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(types.SanitizeText(format), sanitizeArgs(args)...)
}

// 输出 HTTP 代理生命周期相关的最小日志，未注入时保持静默。
func (m *HTTPProxyManager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(types.SanitizeText(format), sanitizeArgs(args)...)
}

// 归一化代理模式配置并按需补齐默认值。
func normalizeProxyConfig(cfg *config.KernelConfig, mode string, fillDefaults bool) (config.KernelConfig, error) {
	if cfg == nil {
		return config.KernelConfig{}, errNilConfig
	}
	clone := *cfg
	clone.Mode = mode
	if fillDefaults {
		clone.FillDefaults()
	}
	if err := clone.Validate(); err != nil {
		return config.KernelConfig{}, err
	}
	return clone, nil
}
