package kernel_test

import (
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// 验证 CONNECT-IP 会话参数会从连接参数中生成。
func TestBuildConnectIPOptions(t *testing.T) {
	options := kernel.BuildConnectIPOptions(kernel.HTTP3Options{
		Authority:       config.DefaultEndpoint,
		EnableDatagrams: true,
	})
	if options.Authority != config.DefaultEndpoint {
		t.Fatalf("expected authority %q, got %q", config.DefaultEndpoint, options.Authority)
	}
	if options.Protocol != kernel.ProtocolConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolConnectIP, options.Protocol)
	}
	if !options.EnableDatagrams {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证会话建立器会暴露最小状态快照。
func TestNewConnectIPSessionManager(t *testing.T) {
	manager, err := kernel.NewConnectIPSessionManager(config.KernelConfig{
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
		t.Fatalf("expected session manager creation success, got %v", err)
	}
	snapshot := manager.Snapshot()
	if snapshot.State != kernel.SessionStateIdle {
		t.Fatalf("expected idle state, got %q", snapshot.State)
	}
	if snapshot.Protocol != kernel.ProtocolConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolConnectIP, snapshot.Protocol)
	}
}
