package kernel

import (
	"context"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
)

func TestBuildConnectStreamOptions(t *testing.T) {
	h3 := HTTP3Options{
		Authority:       "162.159.197.1:443",
		EnableDatagrams: true,
	}

	opts := BuildConnectStreamOptions(h3, "example.com", "443")

	if opts.Authority != "162.159.197.1:443" {
		t.Errorf("expected authority %q, got %q", "162.159.197.1:443", opts.Authority)
	}
	if opts.TargetHost != "example.com" {
		t.Errorf("expected target host %q, got %q", "example.com", opts.TargetHost)
	}
	if opts.TargetPort != "443" {
		t.Errorf("expected target port %q, got %q", "443", opts.TargetPort)
	}
	if opts.Protocol != ProtocolConnectStream {
		t.Errorf("expected protocol %q, got %q", ProtocolConnectStream, opts.Protocol)
	}
}

func TestConnectStreamManager_StateTransitions(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	snapshot := mgr.Snapshot()
	if snapshot.State != StreamStateIdle {
		t.Errorf("expected state %q, got %q", StreamStateIdle, snapshot.State)
	}

	mgr.SetReady()
	snapshot = mgr.Snapshot()
	if snapshot.State != StreamStateReady {
		t.Errorf("expected state %q, got %q", StreamStateReady, snapshot.State)
	}

	if err := mgr.Close(); err != nil {
		t.Errorf("failed to close: %v", err)
	}
	snapshot = mgr.Snapshot()
	if snapshot.State != StreamStateIdle {
		t.Errorf("expected state %q, got %q", StreamStateIdle, snapshot.State)
	}
}

func TestConnectStreamManager_Stats(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	mgr.RecordHandshakeLatency(100 * time.Millisecond)
	mgr.AddTxBytes(1024)
	mgr.AddRxBytes(2048)

	stats := mgr.Stats()
	if stats.HandshakeLatency <= 0 {
		t.Error("expected positive handshake latency")
	}
	if stats.TxBytes != 1024 {
		t.Errorf("expected tx bytes %d, got %d", 1024, stats.TxBytes)
	}
	if stats.RxBytes != 2048 {
		t.Errorf("expected rx bytes %d, got %d", 2048, stats.RxBytes)
	}
}

func TestParseConnectTarget(t *testing.T) {
	tests := []struct {
		url      string
		wantHost string
		wantPort string
	}{
		{"example.com:443", "example.com", "443"},
		{"https://example.com:8443", "example.com", "8443"},
		{"http://example.com", "example.com", "443"},
		{"example.com", "example.com", "443"},
		{"192.168.1.1:8080", "192.168.1.1", "8080"},
	}

	for _, tt := range tests {
		host, port, err := parseConnectTarget(tt.url)
		if err != nil {
			t.Errorf("parseConnectTarget(%q) error: %v", tt.url, err)
			continue
		}
		if host != tt.wantHost {
			t.Errorf("parseConnectTarget(%q) host = %q, want %q", tt.url, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("parseConnectTarget(%q) port = %q, want %q", tt.url, port, tt.wantPort)
		}
	}
}

func TestActiveStream_ReadWrite(t *testing.T) {
	stream := &activeStream{
		info: StreamInfo{
			RemoteAddr: "example.com:443",
			Protocol:   ProtocolConnectStream,
		},
		local:  "127.0.0.1:40000",
		remote: "example.com:443",
	}

	if stream.conn != nil {
		t.Error("expected nil conn for unconnected stream")
	}

	_, err := stream.Read([]byte{})
	if err == nil {
		t.Error("expected error when reading from unconnected stream")
	}

	_, err = stream.Write([]byte("test"))
	if err == nil {
		t.Error("expected error when writing to unconnected stream")
	}
}

func TestConnectStreamManager_OpenStream_NotReady(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = mgr.OpenStream(ctx, "example.com", "443")
	if err == nil {
		t.Error("expected error when opening stream in idle state")
	}
}

func TestConnectStreamManager_StreamEndpoint_NotFound(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	mgr.SetReady()

	endpoint := mgr.StreamEndpoint("nonexistent.example.com", "443")
	if endpoint != nil {
		t.Error("expected nil endpoint for nonexistent stream")
	}
}

func TestConnectStreamManager_CloseStream_NotFound(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	err = mgr.CloseStream("nonexistent.example.com", "443")
	if err != nil {
		t.Errorf("expected no error when closing nonexistent stream: %v", err)
	}
}
