package kernel_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// 验证协议参数映射会以表驱动方式覆盖 CONNECT-IP 协议解析结果。
func TestBuildConnectIPOptionsTableDriven(t *testing.T) {
	tests := []struct {
		name string
		h3   kernel.HTTP3Options
	}{
		{
			name: "datagrams enabled",
			h3: kernel.HTTP3Options{
				Authority:       config.DefaultEndpoint,
				EnableDatagrams: true,
			},
		},
		{
			name: "datagrams disabled",
			h3: kernel.HTTP3Options{
				Authority:       "162.159.193.1:443",
				EnableDatagrams: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := kernel.BuildConnectIPOptions(tt.h3)
			if options.Authority != tt.h3.Authority {
				t.Fatalf("expected authority %q, got %q", tt.h3.Authority, options.Authority)
			}
			if options.Protocol != kernel.ProtocolConnectIP {
				t.Fatalf("expected protocol %q, got %q", kernel.ProtocolConnectIP, options.Protocol)
			}
			if options.EnableDatagrams != tt.h3.EnableDatagrams {
				t.Fatalf("expected datagrams %v, got %v", tt.h3.EnableDatagrams, options.EnableDatagrams)
			}
		})
	}
}

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
	if snapshot.Protocol != kernel.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolCFConnectIP, snapshot.Protocol)
	}
}

// 验证 CONNECT-IP 会话管理器会暴露流量与时延统计入口。
func TestConnectIPSessionManagerStats(t *testing.T) {
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

	manager.RecordHandshakeLatency(85 * time.Millisecond)
	manager.AddTxBytes(64)
	manager.AddRxBytes(96)

	stats := manager.Stats()
	if stats.HandshakeLatency != 85*time.Millisecond {
		t.Fatalf("expected handshake latency 85ms, got %s", stats.HandshakeLatency)
	}
	if stats.TxBytes != 64 {
		t.Fatalf("expected tx bytes 64, got %d", stats.TxBytes)
	}
	if stats.RxBytes != 96 {
		t.Fatalf("expected rx bytes 96, got %d", stats.RxBytes)
	}
}

// 验证会话快照会复制路由切片，避免调用方修改内部状态。
func TestConnectIPSessionManagerSnapshotCopiesRoutes(t *testing.T) {
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

	info := kernel.SessionInfo{
		IPv4:   "172.16.0.2/32",
		Routes: []string{"0.0.0.0/0", "::/0"},
	}
	manager.UpdateSessionInfo(info)

	snapshot := manager.Snapshot()
	info.Routes[0] = "mutated-source"
	snapshot.Routes[0] = "mutated-snapshot"

	again := manager.Snapshot()
	if again.Routes[0] != "0.0.0.0/0" {
		t.Fatalf("expected copied routes in snapshot, got %+v", again.Routes)
	}
}
