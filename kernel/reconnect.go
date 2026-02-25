package kernel

import "time"

// RetryPolicy 描述有限重试与退避的最小参数。
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// ConnectionEvent 描述连接状态变化事件。
type ConnectionEvent struct {
	State   string
	Reason  string
	Attempt int
}

// KeepaliveManager 管理保活事件与重连策略骨架。
type KeepaliveManager struct {
	policy RetryPolicy
	events []ConnectionEvent
}

// Allow 判断当前重试次数是否仍被允许。
func (p RetryPolicy) Allow(attempt int) bool {
	if p.MaxAttempts <= 0 {
		return false
	}
	return attempt <= p.MaxAttempts
}

// Backoff 计算当前重试次数对应的退避时间。
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

// NewKeepaliveManager 创建保活与重连骨架管理器。
func NewKeepaliveManager(policy RetryPolicy) *KeepaliveManager {
	return &KeepaliveManager{policy: policy}
}

// MarkConnected 记录连接进入就绪态。
func (m *KeepaliveManager) MarkConnected() {
	m.events = append(m.events, ConnectionEvent{State: ConnStateReady})
}

// MarkDisconnected 记录连接断开及其原因。
func (m *KeepaliveManager) MarkDisconnected(reason string) {
	m.events = append(m.events, ConnectionEvent{State: ConnStateConnecting, Reason: reason})
}

// Events 返回当前记录的状态变化事件。
func (m *KeepaliveManager) Events() []ConnectionEvent {
	return append([]ConnectionEvent(nil), m.events...)
}
