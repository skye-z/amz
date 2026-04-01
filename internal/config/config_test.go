package config_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
)

const (
	testConfigExampleSNI      = "example.com"
	testConfigExampleEndpoint = "example.com:443"
	testConfigWarpSNI         = "warp.cloudflare.com"
)

func TestKernelConfigFillDefaults(t *testing.T) {
	cfg := config.KernelConfig{}
	cfg.FillDefaults()
	if cfg.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected default endpoint %q, got %q", config.DefaultEndpoint, cfg.Endpoint)
	}
	if cfg.SNI != config.DefaultSNI {
		t.Fatalf("expected default sni %q, got %q", config.DefaultSNI, cfg.SNI)
	}
	if cfg.MTU != config.DefaultMTU {
		t.Fatalf("expected default mtu %d, got %d", config.DefaultMTU, cfg.MTU)
	}
	if cfg.Keepalive != config.DefaultKeepalive {
		t.Fatalf("expected keepalive %s, got %s", config.DefaultKeepalive, cfg.Keepalive)
	}
	if cfg.ConnectTimeout != config.DefaultConnectTimeout {
		t.Fatalf("expected connect timeout %s, got %s", config.DefaultConnectTimeout, cfg.ConnectTimeout)
	}
	if cfg.Mode != config.ModeTUN {
		t.Fatalf("expected default mode %q, got %q", config.ModeTUN, cfg.Mode)
	}
}

func TestDefaultSNIUsesWarpCloudflareCom(t *testing.T) {
	if config.DefaultSNI != testConfigWarpSNI {
		t.Fatalf("expected default sni %q, got %q", testConfigWarpSNI, config.DefaultSNI)
	}
}

func TestKernelConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.KernelConfig
	}{
		{name: "missing endpoint", cfg: config.KernelConfig{Endpoint: "", SNI: testConfigExampleSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN}},
		{name: "invalid mtu", cfg: config.KernelConfig{Endpoint: testConfigExampleEndpoint, SNI: testConfigExampleSNI, MTU: 100, Mode: config.ModeTUN}},
		{name: "invalid mode", cfg: config.KernelConfig{Endpoint: testConfigExampleEndpoint, SNI: testConfigExampleSNI, MTU: config.DefaultMTU, Mode: "invalid"}},
		{name: "invalid keepalive", cfg: config.KernelConfig{Endpoint: testConfigExampleEndpoint, SNI: testConfigExampleSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, Keepalive: -1 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
	valid := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		Keepalive:      config.DefaultKeepalive,
		ConnectTimeout: config.DefaultConnectTimeout,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}
