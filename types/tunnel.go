package types

import (
	"context"
	"errors"
	"time"
)

const (
	// StateIdle 表示实例已创建但尚未运行。
	StateIdle = "idle"
	// StateRunning 表示实例已经进入运行状态。
	StateRunning = "running"
	// StateStopped 表示实例已停止且不可继续复用。
	StateStopped = "stopped"
)

const (
	// EventTypeStateChanged 表示生命周期状态变化。
	EventTypeStateChanged = "state_changed"
)

var (
	// ErrInvalidConfig 表示配置不满足基础约束。
	ErrInvalidConfig = errors.New("invalid config")
	// ErrUnsupportedMode 表示当前运行模式尚未实现。
	ErrUnsupportedMode = errors.New("unsupported mode")
)

// Event 描述基础阶段可向上层暴露的状态变化。
type Event struct {
	Type      string
	State     string
	Message   string
	Timestamp time.Time
}

// EventHandler 用于向上层分发基础生命周期事件。
type EventHandler func(Event)

// Stats 描述基础阶段可观测的最小统计信息。
type Stats struct {
	StartCount int
	StopCount  int
}

// Tunnel 约定上层可依赖的最小生命周期接口。
type Tunnel interface {
	Start(context.Context) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() Stats
}
