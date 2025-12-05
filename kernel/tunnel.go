package kernel

import (
	"context"
	"errors"
	"sync"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

var errNilConfig = errors.New("kernel config is required")

// Tunnel 用于承接第一阶段的最小生命周期实现。
type Tunnel struct {
	mu    sync.Mutex
	cfg   config.KernelConfig
	state string
	stats types.Stats
}

// NewTunnel 创建一个通过基础配置校验的空实现隧道。
func NewTunnel(cfg *config.KernelConfig) (*Tunnel, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	clone := *cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return &Tunnel{
		cfg:   clone,
		state: types.StateIdle,
	}, nil
}

// Start 记录启动次数并切换到运行态。
func (t *Tunnel) Start(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == types.StateStopped {
		return errors.New("tunnel already stopped")
	}
	t.state = types.StateRunning
	t.stats.StartCount++
	return nil
}

// Stop 记录停止次数并切换到停止态。
func (t *Tunnel) Stop(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == types.StateStopped {
		return nil
	}
	t.state = types.StateStopped
	t.stats.StopCount++
	return nil
}

// Close 复用停止流程，便于上层统一清理。
func (t *Tunnel) Close() error {
	return t.Stop(context.Background())
}

// State 返回当前生命周期状态。
func (t *Tunnel) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// Stats 返回基础阶段的统计快照。
func (t *Tunnel) Stats() types.Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}
