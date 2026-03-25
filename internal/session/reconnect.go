package session

import (
	"context"
	"time"

	"github.com/skye-z/amz/internal/config"
)

// 描述有限重试与退避的最小参数。
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// 描述连接状态变化事件。
type ConnectionEvent struct {
	State   string
	Reason  string
	Attempt int
}

// 管理保活事件与重连策略骨架。
type KeepaliveManager struct {
	policy RetryPolicy
	events []ConnectionEvent
	stats  connectionStats
}

// 判断当前重试次数是否仍被允许。
func (p RetryPolicy) Allow(attempt int) bool {
	if p.MaxAttempts <= 0 {
		return false
	}
	return attempt <= p.MaxAttempts
}

// 计算当前重试次数对应的退避时间。
func (p RetryPolicy) Backoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	delay := time.Duration(attempt) * p.BaseDelay
	if p.MaxDelay > 0 && delay > p.MaxDelay {
		return p.MaxDelay
	}
	return delay
}

// 创建保活与重连骨架管理器。
func NewKeepaliveManager(policy RetryPolicy) *KeepaliveManager {
	return &KeepaliveManager{policy: policy}
}

// 记录连接进入就绪态。
func (m *KeepaliveManager) MarkConnected() {
	m.events = append(m.events, ConnectionEvent{State: ConnStateReady})
}

// 记录连接断开及其原因。
func (m *KeepaliveManager) MarkDisconnected(reason string) {
	m.events = append(m.events, ConnectionEvent{State: ConnStateConnecting, Reason: reason})
}

// 记录一次重连尝试并附带原因与次数。
func (m *KeepaliveManager) RecordReconnect(reason string, attempt int) {
	m.stats.AddReconnect()
	m.events = append(m.events, ConnectionEvent{
		State:   ConnStateConnecting,
		Reason:  reason,
		Attempt: attempt,
	})
}

// 返回当前记录的状态变化事件。
func (m *KeepaliveManager) Events() []ConnectionEvent {
	return append([]ConnectionEvent(nil), m.events...)
}

// 返回保活与重连阶段统计快照。
func (m *KeepaliveManager) Stats() config.Stats {
	return m.stats.Snapshot()
}

// 按重试策略执行一次同步重连流程。
func (m *KeepaliveManager) Reconnect(ctx context.Context, reason string, fn func(context.Context, int) error) error {
	m.MarkDisconnected(reason)
	var lastErr error
	for attempt := 1; m.policy.Allow(attempt); attempt++ {
		if err := fn(ctx, attempt); err != nil {
			m.RecordReconnect(reason, attempt)
			lastErr = err
			continue
		}
		m.MarkConnected()
		return nil
	}
	return lastErr
}
