package amz_test

import (
	"testing"

	"github.com/skye-z/amz"
	"github.com/skye-z/amz/config"
)

func TestNewSOCKS5Proxy(t *testing.T) {
	cfg := &config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		SOCKS:    config.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	}
	cfg.FillDefaults()

	runtime, err := amz.NewSOCKS5Proxy(cfg)
	if err != nil {
		t.Fatalf("expected proxy creation success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil runtime")
	}
}
