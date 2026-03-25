package session

import (
	"testing"

	"github.com/skye-z/amz/internal/config"
)

// 验证会话管理器可保存地址与路由信息。
func TestConnectIPSessionManagerUpdateSessionInfo(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
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

	manager.UpdateSessionInfo(SessionInfo{
		IPv4:   "172.16.0.2/32",
		IPv6:   "2606:4700:110:8765::2/128",
		Routes: []string{"0.0.0.0/0", "::/0"},
	})

	snapshot := manager.Snapshot()
	if snapshot.IPv4 != "172.16.0.2/32" {
		t.Fatalf("expected ipv4 in snapshot, got %q", snapshot.IPv4)
	}
	if snapshot.IPv6 != "2606:4700:110:8765::2/128" {
		t.Fatalf("expected ipv6 in snapshot, got %q", snapshot.IPv6)
	}
	if len(snapshot.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(snapshot.Routes))
	}
}
