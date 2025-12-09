package config_test

import (
	"testing"

	"github.com/skye-z/amz/config"
)

// 验证模式化配置字段会按运行模式参与校验。
func TestKernelConfigValidateByMode(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.KernelConfig
		wantErr bool
	}{
		{
			name: "tun requires name",
			cfg: config.KernelConfig{
				Endpoint:       config.DefaultEndpoint,
				SNI:            config.DefaultSNI,
				MTU:            config.DefaultMTU,
				Mode:           config.ModeTUN,
				ConnectTimeout: config.DefaultConnectTimeout,
				Keepalive:      config.DefaultKeepalive,
			},
			wantErr: true,
		},
		{
			name: "socks requires listen address",
			cfg: config.KernelConfig{
				Endpoint:       config.DefaultEndpoint,
				SNI:            config.DefaultSNI,
				MTU:            config.DefaultMTU,
				Mode:           config.ModeSOCKS,
				ConnectTimeout: config.DefaultConnectTimeout,
				Keepalive:      config.DefaultKeepalive,
			},
			wantErr: true,
		},
		{
			name: "http requires listen address",
			cfg: config.KernelConfig{
				Endpoint:       config.DefaultEndpoint,
				SNI:            config.DefaultSNI,
				MTU:            config.DefaultMTU,
				Mode:           config.ModeHTTP,
				ConnectTimeout: config.DefaultConnectTimeout,
				Keepalive:      config.DefaultKeepalive,
			},
			wantErr: true,
		},
		{
			name: "valid socks config",
			cfg: config.KernelConfig{
				Endpoint:       config.DefaultEndpoint,
				SNI:            config.DefaultSNI,
				MTU:            config.DefaultMTU,
				Mode:           config.ModeSOCKS,
				ConnectTimeout: config.DefaultConnectTimeout,
				Keepalive:      config.DefaultKeepalive,
				SOCKS: config.SOCKSConfig{
					ListenAddress: "127.0.0.1:1080",
				},
			},
			wantErr: false,
		},
		{
			name: "valid tun config",
			cfg: config.KernelConfig{
				Endpoint:       config.DefaultEndpoint,
				SNI:            config.DefaultSNI,
				MTU:            config.DefaultMTU,
				Mode:           config.ModeTUN,
				ConnectTimeout: config.DefaultConnectTimeout,
				Keepalive:      config.DefaultKeepalive,
				TUN: config.TUNConfig{
					Name: "igara0",
				},
			},
			wantErr: false,
		},
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

// 验证默认值填充会为代理模式补齐监听地址。
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
