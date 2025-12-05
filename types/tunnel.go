package types

import "context"

const (
	// StateIdle 表示实例已创建但尚未运行。
	StateIdle = "idle"
	// StateRunning 表示实例已经进入运行状态。
	StateRunning = "running"
	// StateStopped 表示实例已停止且不可继续复用。
	StateStopped = "stopped"
)

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
