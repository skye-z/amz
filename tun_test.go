package amz_test

import (
	"testing"

	"github.com/skye-z/amz"
	"github.com/skye-z/amz/config"
)

func TestNewTunnel(t *testing.T) {
	cfg := &config.KernelConfig{
		Mode:     config.ModeTUN,
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		TUN:      config.TUNConfig{Name: "igara0"},
	}
	cfg.FillDefaults()

	runtime, err := amz.NewTunnel(cfg)
	if err != nil {
		t.Fatalf("expected tunnel creation success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil runtime")
	}
}
