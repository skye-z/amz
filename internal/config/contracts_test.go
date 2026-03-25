package config_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
)

func TestEvent(t *testing.T) {
	event := config.Event{Type: config.EventTypeStateChanged, State: config.StateRunning, Message: "connected", Timestamp: time.Unix(1700000000, 0)}
	if event.Type != config.EventTypeStateChanged {
		t.Fatalf("expected event type %q, got %q", config.EventTypeStateChanged, event.Type)
	}
	if event.State != config.StateRunning {
		t.Fatalf("expected state %q, got %q", config.StateRunning, event.State)
	}
	if event.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}
}

func TestEventHandler(t *testing.T) {
	called := false
	handler := config.EventHandler(func(event config.Event) {
		called = true
		if event.Type != config.EventTypeStateChanged {
			t.Fatalf("expected event type %q, got %q", config.EventTypeStateChanged, event.Type)
		}
	})
	handler(config.Event{Type: config.EventTypeStateChanged, Timestamp: time.Now()})
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestStatsStructured(t *testing.T) {
	stats := config.Stats{StartCount: 2, StopCount: 1, ReconnectCount: 3, TxBytes: 128, RxBytes: 256, HandshakeLatency: 150 * time.Millisecond}
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

func TestStatsFields(t *testing.T) {
	stats := config.Stats{StartCount: 1, StopCount: 2, ReconnectCount: 4, TxBytes: 64, RxBytes: 96, HandshakeLatency: 42 * time.Millisecond}
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
