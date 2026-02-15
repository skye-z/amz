package kernel_test

import (
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// 验证 QUIC 连接参数会从内核配置中生成。
func TestBuildQUICOptions(t *testing.T) {
	options, err := kernel.BuildQUICOptions(config.KernelConfig{
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
		t.Fatalf("expected quic options, got %v", err)
	}
	if options.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, options.Endpoint)
	}
	if options.ServerName != config.DefaultSNI {
		t.Fatalf("expected server name %q, got %q", config.DefaultSNI, options.ServerName)
	}
	if options.EnableDatagrams != true {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证 HTTP/3 连接参数会复用 QUIC 连接信息。
func TestBuildHTTP3Options(t *testing.T) {
	http3Options := kernel.BuildHTTP3Options(kernel.QUICOptions{
		Endpoint:        config.DefaultEndpoint,
		ServerName:      config.DefaultSNI,
		EnableDatagrams: true,
	})
	if http3Options.Authority != config.DefaultEndpoint {
		t.Fatalf("expected authority %q, got %q", config.DefaultEndpoint, http3Options.Authority)
	}
	if !http3Options.EnableDatagrams {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证连接管理器会暴露最小状态快照。
func TestConnectionManagerSnapshot(t *testing.T) {
	manager, err := kernel.NewConnectionManager(config.KernelConfig{
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
		t.Fatalf("expected manager creation success, got %v", err)
	}
	snapshot := manager.Snapshot()
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if snapshot.State != kernel.ConnStateIdle {
		t.Fatalf("expected idle state, got %q", snapshot.State)
	}
}
