package types

import (
	"context"
	"errors"
	"time"
)

const (
	// 表示实例已创建但尚未运行。
	StateIdle = "idle"
	// 表示实例已经进入运行状态。
	StateRunning = "running"
	// 表示实例已停止且不可继续复用。
	StateStopped = "stopped"
)

const (
	// 表示生命周期状态变化。
	EventTypeStateChanged = "state_changed"
)

var (
	// 表示配置不满足基础约束。
	ErrInvalidConfig = errors.New("invalid config")
	// 表示当前运行模式尚未实现。
	ErrUnsupportedMode = errors.New("unsupported mode")
	// 表示当前能力仅有占位骨架，尚未接入真实实现。
	ErrNotImplemented = errors.New("not implemented")
	// 表示 Cloudflare 兼容层处理失败。
	ErrCloudflareCompat = errors.New("cloudflare compatibility error")
	// 表示鉴权或授权阶段被远端拒绝。
	ErrAuthenticationFailed = errors.New("authentication failed")
)

// 描述基础阶段可向上层暴露的状态变化。
type Event struct {
	Type      string
	State     string
	Message   string
	Timestamp time.Time
}

// 用于向上层分发基础生命周期事件。
type EventHandler func(Event)

// 描述基础阶段可观测的最小统计信息。
type Stats struct {
	StartCount       int
	StopCount        int
	ReconnectCount   int
	TxBytes          int
	RxBytes          int
	HandshakeLatency time.Duration
}

// 描述便于序列化和结构化输出的生命周期统计。
type LifecycleStats struct {
	Starts     int `json:"starts"`
	Stops      int `json:"stops"`
	Reconnects int `json:"reconnects"`
}

// 描述结构化流量统计。
type TrafficStats struct {
	TxBytes    int `json:"tx_bytes"`
	RxBytes    int `json:"rx_bytes"`
	TotalBytes int `json:"total_bytes"`
}

// 描述结构化时延统计。
type TimingStats struct {
	HandshakeLatencyMillis int64 `json:"handshake_latency_ms"`
}

// 描述结构化统计输出。
type StructuredStats struct {
	Lifecycle LifecycleStats `json:"lifecycle"`
	Traffic   TrafficStats   `json:"traffic"`
	Timing    TimingStats    `json:"timing"`
}

// Structured 将平铺统计转换为结构化视图，便于日志、JSON 和 CLI 输出。
func (s Stats) Structured() StructuredStats {
	return StructuredStats{
		Lifecycle: LifecycleStats{
			Starts:     s.StartCount,
			Stops:      s.StopCount,
			Reconnects: s.ReconnectCount,
		},
		Traffic: TrafficStats{
			TxBytes:    s.TxBytes,
			RxBytes:    s.RxBytes,
			TotalBytes: s.TxBytes + s.RxBytes,
		},
		Timing: TimingStats{
			HandshakeLatencyMillis: s.HandshakeLatency.Milliseconds(),
		},
	}
}

// Fields 返回适合结构化日志的扁平字段映射。
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

// 约定上层可依赖的最小生命周期接口。
type Tunnel interface {
	Start(context.Context) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() Stats
}
