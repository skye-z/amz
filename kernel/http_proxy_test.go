package kernel_test

import (
	"context"
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/types"
)

// 验证 HTTP 代理管理器会暴露配置中的监听地址与初始状态。
func TestNewHTTPProxyManager(t *testing.T) {
	manager, err := kernel.NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: "127.0.0.1:18080",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if manager.ListenAddress() != "127.0.0.1:18080" {
		t.Fatalf("expected listen address to match config, got %q", manager.ListenAddress())
	}
	if manager.State() != types.StateIdle {
		t.Fatalf("expected idle state, got %q", manager.State())
	}
	stats := manager.Stats()
	if stats.StartCount != 0 || stats.StopCount != 0 {
		t.Fatalf("expected zero stats, got %+v", stats)
	}
}

// 验证 HTTP 代理管理器会记录启动停止次数并切换生命周期状态。
func TestHTTPProxyManagerStartStop(t *testing.T) {
	manager, err := kernel.NewHTTPProxyManager(config.KernelConfig{
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

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if manager.State() != types.StateRunning {
		t.Fatalf("expected running state, got %q", manager.State())
	}

	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop success, got %v", err)
	}
	if manager.State() != types.StateStopped {
		t.Fatalf("expected stopped state, got %q", manager.State())
	}

	stats := manager.Stats()
	if stats.StartCount != 1 {
		t.Fatalf("expected one start, got %d", stats.StartCount)
	}
	if stats.StopCount != 1 {
		t.Fatalf("expected one stop, got %d", stats.StopCount)
	}
}

// 验证 HTTP 代理管理器会复用 HTTP 模式的最小配置校验。
func TestNewHTTPProxyManagerRejectsInvalidConfig(t *testing.T) {
	_, err := kernel.NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: "   ",
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
