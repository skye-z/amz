package kernel_test

import (
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// 验证默认 Cloudflare quirks 会启用最小兼容开关。
func TestDefaultCloudflareQuirks(t *testing.T) {
	quirks := kernel.DefaultCloudflareQuirks()

	if !quirks.UseCFConnectIP {
		t.Fatal("expected cf-connect-ip quirk enabled")
	}
	if !quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
	if !quirks.MapUnauthorizedToAuthError {
		t.Fatal("expected unauthorized mapping enabled")
	}
	if quirks.Name == "" {
		t.Fatal("expected quirk set name")
	}
}

// 验证兼容层入口会复用连接参数并暴露最小 quirks。
func TestNewCloudflareCompatLayer(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != kernel.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.UseCFConnectIP {
		t.Fatal("expected cf-connect-ip quirk enabled")
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}
