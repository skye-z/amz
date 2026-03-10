package kernel

import (
	"context"
	"errors"
	"sync"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

var errProxyAlreadyStopped = errors.New("proxy manager already stopped")

// SOCKSManager 管理 SOCKS5 模式的最小监听骨架。
type SOCKSManager struct {
	mu     sync.Mutex
	cfg    config.KernelConfig
	state  string
	stats  types.Stats
	listen string
}

// HTTPProxyManager 管理 HTTP 代理模式的最小监听骨架。
type HTTPProxyManager struct {
	mu     sync.Mutex
	cfg    config.KernelConfig
	state  string
	stats  types.Stats
	listen string
}

// NewSOCKSManager 创建 SOCKS5 模式的最小管理器。
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

// NewHTTPProxyManager 创建 HTTP 代理模式的最小管理器。
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

// ListenAddress 返回 SOCKS5 管理器的监听地址快照。
func (m *SOCKSManager) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listen
}

// Start 记录启动次数并切换到运行态。
func (m *SOCKSManager) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return errProxyAlreadyStopped
	}
	m.state = types.StateRunning
	m.stats.StartCount++
	return nil
}

// Stop 记录停止次数并切换到停止态。
func (m *SOCKSManager) Stop(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return nil
	}
	m.state = types.StateStopped
	m.stats.StopCount++
	return nil
}

// Close 复用停止流程，便于上层统一回收。
func (m *SOCKSManager) Close() error {
	return m.Stop(context.Background())
}

// State 返回 SOCKS5 管理器当前状态。
func (m *SOCKSManager) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Stats 返回 SOCKS5 管理器统计快照。
func (m *SOCKSManager) Stats() types.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// ListenAddress 返回 HTTP 代理管理器的监听地址快照。
func (m *HTTPProxyManager) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listen
}

// Start 记录启动次数并切换到运行态。
func (m *HTTPProxyManager) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return errProxyAlreadyStopped
	}
	m.state = types.StateRunning
	m.stats.StartCount++
	return nil
}

// Stop 记录停止次数并切换到停止态。
func (m *HTTPProxyManager) Stop(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == types.StateStopped {
		return nil
	}
	m.state = types.StateStopped
	m.stats.StopCount++
	return nil
}

// Close 复用停止流程，便于上层统一回收。
func (m *HTTPProxyManager) Close() error {
	return m.Stop(context.Background())
}

// State 返回 HTTP 代理管理器当前状态。
func (m *HTTPProxyManager) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Stats 返回 HTTP 代理管理器统计快照。
func (m *HTTPProxyManager) Stats() types.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
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
