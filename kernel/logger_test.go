package kernel_test

import (
	"context"
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

// recordLogger 用于记录内核输出的最小日志消息。
type recordLogger struct {
	entries []string
}

// 记录格式化后的日志内容，便于断言库级日志行为。
func (l *recordLogger) Printf(format string, args ...any) {
	l.entries = append(l.entries, format)
}

// 验证默认未注入 logger 时生命周期操作保持静默。
func TestTunnelLifecycleSilentByDefault(t *testing.T) {
	tunnel, err := kernel.NewTunnel(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeTUN,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := tunnel.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := tunnel.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop success, got %v", err)
	}
}

// 验证注入 logger 后会记录最小生命周期消息。
func TestTunnelLifecycleUsesInjectedLogger(t *testing.T) {
	logger := &recordLogger{}
	tunnel, err := kernel.NewTunnel(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeTUN,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := tunnel.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := tunnel.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop success, got %v", err)
	}

	if len(logger.entries) != 2 {
		t.Fatalf("expected two log entries, got %d", len(logger.entries))
	}
	if logger.entries[0] != "tunnel start: mode=%s endpoint=%s" {
		t.Fatalf("expected start log template, got %q", logger.entries[0])
	}
	if logger.entries[1] != "tunnel stop: mode=%s endpoint=%s" {
		t.Fatalf("expected stop log template, got %q", logger.entries[1])
	}
	if got := tunnel.Logger(); got != logger {
		t.Fatalf("expected logger injection to be preserved, got %#v", got)
	}
}
