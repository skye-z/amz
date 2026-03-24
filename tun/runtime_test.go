package tun_test

import (
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/tun"
	"github.com/skye-z/amz/types"
)

// 验证空实现隧道在基础设施阶段可被安全创建。
func TestNewTunnel(t *testing.T) {
	tunnel, err := tun.NewTunnel(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeTUN,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tunnel == nil {
		t.Fatal("expected tunnel instance")
	}
	if tunnel.State() != types.StateIdle {
		t.Fatalf("expected idle state, got %q", tunnel.State())
	}
	stats := tunnel.Stats()
	if stats.StartCount != 0 || stats.StopCount != 0 {
		t.Fatalf("expected zero stats, got %+v", stats)
	}
}

// 验证空实现隧道会复用配置校验结果。
func TestNewTunnelRejectsInvalidConfig(t *testing.T) {
	_, err := tun.NewTunnel(&config.KernelConfig{MTU: 100})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
