package kernel_test

import (
	"context"
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/types"
)

// 验证 SOCKS5 管理器会补齐最小监听地址并维持空闲态。
func TestNewSOCKSManagerFillsDefaultListenAddress(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeSOCKS,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if mgr == nil {
		t.Fatal("expected socks manager")
	}
	if mgr.ListenAddress() != config.DefaultSOCKSListenAddress {
		t.Fatalf("expected default listen address %q, got %q", config.DefaultSOCKSListenAddress, mgr.ListenAddress())
	}
	if mgr.State() != types.StateIdle {
		t.Fatalf("expected idle state, got %q", mgr.State())
	}
}

// 验证 SOCKS5 管理器会记录启动停止次数并暴露状态快照。
func TestSOCKSManagerStartStopAndStats(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeSOCKS,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if mgr.ListenAddress() != "127.0.0.1:0" {
		t.Fatalf("expected explicit listen address, got %q", mgr.ListenAddress())
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start to succeed, got %v", err)
	}
	if mgr.ListenAddress() == "127.0.0.1:0" {
		t.Fatalf("expected runtime listener address to be updated, got %q", mgr.ListenAddress())
	}
	if mgr.State() != types.StateRunning {
		t.Fatalf("expected running state, got %q", mgr.State())
	}
	stats := mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 0 {
		t.Fatalf("expected start stats, got %+v", stats)
	}

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop to succeed, got %v", err)
	}
	if mgr.State() != types.StateStopped {
		t.Fatalf("expected stopped state, got %q", mgr.State())
	}
	stats = mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 1 {
		t.Fatalf("expected stop stats, got %+v", stats)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("expected close to be idempotent, got %v", err)
	}
}
