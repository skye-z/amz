package config

import (
	"strings"
	"testing"
	"time"
)

func TestStatsStructuredAndFields(t *testing.T) {
	stats := Stats{StartCount: 1, StopCount: 2, ReconnectCount: 3, TxBytes: 4, RxBytes: 5, HandshakeLatency: 250 * time.Millisecond}
	structured := stats.Structured()
	if structured.Traffic.TotalBytes != 9 || structured.Timing.HandshakeLatencyMillis != 250 {
		t.Fatalf("unexpected structured stats: %+v", structured)
	}
	fields := stats.Fields()
	if fields["traffic.total_bytes"].(int) != 9 || !strings.Contains(fields["timing.handshake_latency_text"].(string), "250ms") {
		t.Fatalf("unexpected fields: %+v", fields)
	}
}

func TestFillDefaultsForEachModeAndValidateExtraBranches(t *testing.T) {
	cfg := KernelConfig{Endpoint: DefaultEndpoint, SNI: DefaultSNI, Mode: ModeSOCKS}
	cfg.FillDefaults()
	if cfg.SOCKS.ListenAddress != DefaultSOCKSListenAddress {
		t.Fatalf("expected default socks listen, got %q", cfg.SOCKS.ListenAddress)
	}
	cfg = KernelConfig{Endpoint: DefaultEndpoint, SNI: DefaultSNI, Mode: ModeHTTP}
	cfg.FillDefaults()
	if cfg.HTTP.ListenAddress != DefaultHTTPListenAddress {
		t.Fatalf("expected default http listen, got %q", cfg.HTTP.ListenAddress)
	}
	bad := KernelConfig{Endpoint: DefaultEndpoint, SNI: DefaultSNI, MTU: 100, Mode: ModeHTTP, ConnectTimeout: DefaultConnectTimeout, Keepalive: DefaultKeepalive, HTTP: HTTPConfig{ListenAddress: DefaultHTTPListenAddress}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "mtu out of range") {
		t.Fatalf("expected mtu validation error, got %v", err)
	}
	bad = KernelConfig{Endpoint: DefaultEndpoint, SNI: DefaultSNI, MTU: DefaultMTU, Mode: ModeHTTP, ConnectTimeout: DefaultConnectTimeout, Keepalive: -1, HTTP: HTTPConfig{ListenAddress: DefaultHTTPListenAddress}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "keepalive") {
		t.Fatalf("expected keepalive validation error, got %v", err)
	}
}

func TestConnectionStatsMutationHelpers(t *testing.T) {
	var stats ConnectionStats
	stats.RecordHandshakeLatency(15 * time.Millisecond)
	stats.AddTxBytes(10)
	stats.AddTxBytes(-1)
	stats.AddRxBytes(20)
	stats.AddRxBytes(0)
	stats.AddReconnect()

	snapshot := stats.Snapshot()
	if snapshot.HandshakeLatency != 15*time.Millisecond {
		t.Fatalf("unexpected handshake latency: %s", snapshot.HandshakeLatency)
	}
	if snapshot.TxBytes != 10 || snapshot.RxBytes != 20 {
		t.Fatalf("unexpected byte counters: %+v", snapshot)
	}
	if snapshot.ReconnectCount != 1 {
		t.Fatalf("unexpected reconnect count: %+v", snapshot)
	}
}
