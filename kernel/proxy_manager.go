package kernel

import (
	"context"
	"errors"
	"sync"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

var errProxyAlreadyStopped = errors.New("proxy manager already stopped")

// 管理 SOCKS5 模式的最小监听骨架。
type SOCKSManager struct {
	mu     sync.Mutex
	cfg    config.KernelConfig
	state  string
	stats  types.Stats
	listen string
}

// 描述 SOCKS5 管理器的最小配置快照。
type SOCKSSnapshot struct {
	ListenAddress string
	Username      string
	EnableUDP     bool
}

// 管理 HTTP 代理模式的最小监听骨架。
type HTTPProxyManager struct {
	mu     sync.Mutex
	cfg    config.KernelConfig
	state  string
	stats  types.Stats
	listen string
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

// 记录启动次数并切换到运行态。
func (m *SOCKSManager) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return errProxyAlreadyStopped
	}
	m.logf("socks manager start: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.state = types.StateRunning
	m.stats.StartCount++
	return nil
}

// 记录停止次数并切换到停止态。
func (m *SOCKSManager) Stop(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return nil
	}
	m.logf("socks manager stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.state = types.StateStopped
	m.stats.StopCount++
	return nil
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

// 返回 HTTP 代理管理器的监听地址快照。
func (m *HTTPProxyManager) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listen
}

// 记录启动次数并切换到运行态。
func (m *HTTPProxyManager) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return errProxyAlreadyStopped
	}
	m.logf("http proxy start: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.state = types.StateRunning
	m.stats.StartCount++
	return nil
}

// 记录停止次数并切换到停止态。
func (m *HTTPProxyManager) Stop(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return nil
	}
	m.logf("http proxy stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.state = types.StateStopped
	m.stats.StopCount++
	return nil
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

// 输出 SOCKS5 生命周期相关的最小日志，未注入时保持静默。
func (m *SOCKSManager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(format, args...)
}

// 输出 HTTP 代理生命周期相关的最小日志，未注入时保持静默。
func (m *HTTPProxyManager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(format, args...)
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
