package kernel_test

import (
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// 验证 SOCKS5 管理器会暴露认证与 UDP associate 选项。
func TestSOCKSManagerOptions(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:1081",
			Username:      "demo",
			Password:      "secret",
			EnableUDP:     true,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	snapshot := mgr.Snapshot()
	if snapshot.Username != "demo" {
		t.Fatalf("expected username demo, got %q", snapshot.Username)
	}
	if !snapshot.EnableUDP {
		t.Fatal("expected udp associate enabled")
	}
}

// 验证 HTTP 代理管理器会标记复用核心生命周期。
func TestHTTPProxyManagerLifecycleReuse(t *testing.T) {
	mgr, err := kernel.NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: config.DefaultHTTPListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if !mgr.Snapshot().ReuseTunnelLifecycle {
		t.Fatal("expected lifecycle reuse enabled")
	}
}
