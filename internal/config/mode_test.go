package config_test

import (
	"testing"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/testkit"
)

func TestKernelConfigFillDefaultsTrimWhitespaceMode(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.KernelConfig
		wantMode string
		wantName string
	}{
		{name: "whitespace mode falls back to tun", cfg: config.KernelConfig{Mode: " \t\n "}, wantMode: config.ModeTUN, wantName: "igara0"},
		{name: "explicit socks mode stays unchanged", cfg: config.KernelConfig{Mode: config.ModeSOCKS}, wantMode: config.ModeSOCKS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.FillDefaults()
			if cfg.Mode != tt.wantMode {
				t.Fatalf("expected mode %q, got %q", tt.wantMode, cfg.Mode)
			}
			if tt.wantName != "" && cfg.TUN.Name != tt.wantName {
				t.Fatalf("expected tun name %q, got %q", tt.wantName, cfg.TUN.Name)
			}
		})
	}
}

func TestKernelConfigValidateByMode(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.KernelConfig
		wantErr bool
	}{
		{name: "tun requires name", cfg: config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive}, wantErr: true},
		{name: "socks requires listen address", cfg: config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeSOCKS, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive}, wantErr: true},
		{name: "http requires listen address", cfg: config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeHTTP, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive}, wantErr: true},
		{name: "valid socks config", cfg: config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeSOCKS, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, SOCKS: config.SOCKSConfig{ListenAddress: testkit.LocalListenSOCKS}}, wantErr: false},
		{name: "valid tun config", cfg: config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, TUN: config.TUNConfig{Name: "igara0"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestKernelConfigFillProxyDefaults(t *testing.T) {
	cfg := config.KernelConfig{Mode: config.ModeSOCKS}
	cfg.FillDefaults()
	if cfg.SOCKS.ListenAddress == "" {
		t.Fatal("expected default socks listen address")
	}
	httpCfg := config.KernelConfig{Mode: config.ModeHTTP}
	httpCfg.FillDefaults()
	if httpCfg.HTTP.ListenAddress == "" {
		t.Fatal("expected default http listen address")
	}
}

func TestKernelConfigFillDefaultsTrimWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.KernelConfig
		check func(*testing.T, config.KernelConfig)
	}{
		{name: "trim endpoint and sni", cfg: config.KernelConfig{Endpoint: "   ", SNI: "\t"}, check: func(t *testing.T, cfg config.KernelConfig) {
			t.Helper()
			if cfg.Endpoint != config.DefaultEndpoint {
				t.Fatalf("expected default endpoint %q, got %q", config.DefaultEndpoint, cfg.Endpoint)
			}
			if cfg.SNI != config.DefaultSNI {
				t.Fatalf("expected default sni %q, got %q", config.DefaultSNI, cfg.SNI)
			}
		}},
		{name: "trim tun name", cfg: config.KernelConfig{Mode: config.ModeTUN, TUN: config.TUNConfig{Name: "  "}}, check: func(t *testing.T, cfg config.KernelConfig) {
			t.Helper()
			if cfg.TUN.Name != "igara0" {
				t.Fatalf("expected default tun name %q, got %q", "igara0", cfg.TUN.Name)
			}
		}},
		{name: "trim socks listen address", cfg: config.KernelConfig{Mode: config.ModeSOCKS, SOCKS: config.SOCKSConfig{ListenAddress: "\n"}}, check: func(t *testing.T, cfg config.KernelConfig) {
			t.Helper()
			if cfg.SOCKS.ListenAddress != config.DefaultSOCKSListenAddress {
				t.Fatalf("expected default socks listen address %q, got %q", config.DefaultSOCKSListenAddress, cfg.SOCKS.ListenAddress)
			}
		}},
		{name: "trim http listen address", cfg: config.KernelConfig{Mode: config.ModeHTTP, HTTP: config.HTTPConfig{ListenAddress: "\t "}}, check: func(t *testing.T, cfg config.KernelConfig) {
			t.Helper()
			if cfg.HTTP.ListenAddress != config.DefaultHTTPListenAddress {
				t.Fatalf("expected default http listen address %q, got %q", config.DefaultHTTPListenAddress, cfg.HTTP.ListenAddress)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.FillDefaults()
			tt.check(t, cfg)
		})
	}
}
