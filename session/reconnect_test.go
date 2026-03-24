package session

import (
	"testing"
	"time"
)

// 验证退避策略会限制重试次数并计算等待时间。
func TestRetryPolicyBackoff(t *testing.T) {
	policy := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    5 * time.Second,
	}
	if !policy.Allow(2) {
		t.Fatal("expected attempt 2 to be allowed")
	}
	if policy.Allow(4) {
		t.Fatal("expected attempt 4 to be rejected")
	}
	if delay := policy.Backoff(3); delay != 3*time.Second {
		t.Fatalf("expected backoff 3s, got %s", delay)
	}
}

// 验证连接事件会携带状态与原因。
func TestConnectionEvent(t *testing.T) {
	event := ConnectionEvent{
		State:   ConnStateConnecting,
		Reason:  "reconnect",
		Attempt: 2,
	}
	if event.State != ConnStateConnecting {
		t.Fatalf("expected state %q, got %q", ConnStateConnecting, event.State)
	}
	if event.Reason != "reconnect" {
		t.Fatalf("expected reason reconnect, got %q", event.Reason)
	}
}

// 验证保活管理器会输出状态变化事件。
func TestKeepaliveManagerEvents(t *testing.T) {
	manager := NewKeepaliveManager(RetryPolicy{
		MaxAttempts: 2,
		BaseDelay:   1 * time.Second,
		MaxDelay:    3 * time.Second,
	})

	manager.MarkConnected()
	manager.MarkDisconnected("timeout")
	events := manager.Events()

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].State != ConnStateReady {
		t.Fatalf("expected ready event, got %q", events[0].State)
	}
	if events[1].Reason != "timeout" {
		t.Fatalf("expected timeout reason, got %q", events[1].Reason)
	}
}

// 验证保活管理器会累积重连次数统计。
func TestKeepaliveManagerReconnectStats(t *testing.T) {
	manager := NewKeepaliveManager(RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    5 * time.Second,
	})

	manager.RecordReconnect("timeout", 2)

	stats := manager.Stats()
	if stats.ReconnectCount != 1 {
		t.Fatalf("expected reconnect count 1, got %d", stats.ReconnectCount)
	}

	events := manager.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Attempt != 2 {
		t.Fatalf("expected attempt 2, got %d", events[0].Attempt)
	}
	if events[0].Reason != "timeout" {
		t.Fatalf("expected timeout reason, got %q", events[0].Reason)
	}
}
