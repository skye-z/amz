package types_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/types"
)

// 验证平铺统计可以转换为结构化输出。
func TestStatsStructured(t *testing.T) {
	stats := types.Stats{
		StartCount:       2,
		StopCount:        1,
		ReconnectCount:   3,
		TxBytes:          128,
		RxBytes:          256,
		HandshakeLatency: 150 * time.Millisecond,
	}

	structured := stats.Structured()
	if structured.Lifecycle.Starts != 2 || structured.Lifecycle.Stops != 1 || structured.Lifecycle.Reconnects != 3 {
		t.Fatalf("unexpected lifecycle stats: %+v", structured.Lifecycle)
	}
	if structured.Traffic.TxBytes != 128 || structured.Traffic.RxBytes != 256 || structured.Traffic.TotalBytes != 384 {
		t.Fatalf("unexpected traffic stats: %+v", structured.Traffic)
	}
	if structured.Timing.HandshakeLatencyMillis != 150 {
		t.Fatalf("expected handshake latency 150ms, got %+v", structured.Timing)
	}
}

// 验证结构化日志字段会输出稳定键名和值。
func TestStatsFields(t *testing.T) {
	stats := types.Stats{
		StartCount:       1,
		StopCount:        2,
		ReconnectCount:   4,
		TxBytes:          64,
		RxBytes:          96,
		HandshakeLatency: 42 * time.Millisecond,
	}

	fields := stats.Fields()
	want := map[string]any{
		"lifecycle.starts":              1,
		"lifecycle.stops":               2,
		"lifecycle.reconnects":          4,
		"traffic.tx_bytes":              64,
		"traffic.rx_bytes":              96,
		"traffic.total_bytes":           160,
		"timing.handshake_latency_ms":   int64(42),
		"timing.handshake_latency_text": "42ms",
	}
	for key, expected := range want {
		if got := fields[key]; got != expected {
			t.Fatalf("expected %s=%v, got %v", key, expected, got)
		}
	}
}
