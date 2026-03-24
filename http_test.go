package amz_test

import (
	"testing"

	"github.com/skye-z/amz"
	"github.com/skye-z/amz/config"
)

func TestNewHTTPProxy(t *testing.T) {
	cfg := &config.KernelConfig{
		Mode:     config.ModeHTTP,
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		HTTP:     config.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	}
	cfg.FillDefaults()

	runtime, err := amz.NewHTTPProxy(cfg)
	if err != nil {
		t.Fatalf("expected proxy creation success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil runtime")
	}
}
