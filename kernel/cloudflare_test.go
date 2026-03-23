package kernel_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/types"
)

// 验证兼容层错误包装会以表驱动方式覆盖常见错误分支。
func TestCloudflareCompatLayerWrapResponseErrorTableDriven(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	tests := []struct {
		name       string
		statusCode int
		cause      error
		wantQuirk  string
		wantAuth   bool
	}{
		{
			name:       "map unauthorized to auth error",
			statusCode: 401,
			cause:      errors.New("remote unauthorized"),
			wantQuirk:  "unauthorized",
			wantAuth:   true,
		},
		{
			name:       "keep generic response error",
			statusCode: 503,
			cause:      errors.New("temporary unavailable"),
			wantQuirk:  "response_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := layer.WrapResponseError("connect-ip", tt.statusCode, tt.cause)
			if !errors.Is(wrapped, types.ErrCloudflareCompat) {
				t.Fatal("expected wrapped error to match ErrCloudflareCompat")
			}

			var compatErr *types.CloudflareCompatError
			if !errors.As(wrapped, &compatErr) {
				t.Fatal("expected wrapped error to expose CloudflareCompatError")
			}
			if compatErr.Quirk != tt.wantQuirk {
				t.Fatalf("expected quirk %q, got %q", tt.wantQuirk, compatErr.Quirk)
			}

			if tt.wantAuth {
				if !errors.Is(wrapped, types.ErrAuthenticationFailed) {
					t.Fatal("expected unauthorized response to map to authentication failure")
				}
				return
			}
			if !errors.Is(wrapped, tt.cause) {
				t.Fatalf("expected wrapped error to retain cause %v", tt.cause)
			}
		})
	}
}

// 验证默认 Cloudflare quirks 会启用最小兼容开关。
func TestDefaultCloudflareQuirks(t *testing.T) {
	quirks := kernel.DefaultCloudflareQuirks()

	if !quirks.UseCFConnectIP {
		t.Fatal("expected cf-connect-ip quirk enabled")
	}
	if !quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
	if !quirks.MapUnauthorizedToAuthError {
		t.Fatal("expected unauthorized mapping enabled")
	}
	if quirks.Name == "" {
		t.Fatal("expected quirk set name")
	}
}

// 验证兼容层入口会复用连接参数并暴露最小 quirks。
func TestNewCloudflareCompatLayer(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != kernel.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.UseCFConnectIP {
		t.Fatal("expected cf-connect-ip quirk enabled")
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}

// 验证兼容层构造入口会补齐默认配置并产出稳定快照。
func TestNewCloudflareCompatLayerAppliesDefaults(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation with defaults, got %v", err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != kernel.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", kernel.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected default endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}

// 验证兼容层会将未授权响应映射为带上下文的鉴权错误。
func TestCloudflareCompatLayerWrapResponseErrorUnauthorized(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	wrapped := layer.WrapResponseError("connect-ip", 401, errors.New("remote unauthorized"))
	if !errors.Is(wrapped, types.ErrCloudflareCompat) {
		t.Fatal("expected wrapped error to match ErrCloudflareCompat")
	}
	if !errors.Is(wrapped, types.ErrAuthenticationFailed) {
		t.Fatal("expected unauthorized response to map to authentication failure")
	}

	var compatErr *types.CloudflareCompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected wrapped error to expose CloudflareCompatError")
	}
	if compatErr.Quirk != "unauthorized" {
		t.Fatalf("expected quirk %q, got %q", "unauthorized", compatErr.Quirk)
	}
}

// 验证普通响应错误分支会保留原始原因并附带兼容场景。
func TestCloudflareCompatLayerWrapResponseErrorResponseError(t *testing.T) {
	layer, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	cause := errors.New("upstream reset")
	wrapped := layer.WrapResponseError("connect-ip", 503, cause)
	if !errors.Is(wrapped, types.ErrCloudflareCompat) {
		t.Fatal("expected wrapped error to match ErrCloudflareCompat")
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("expected wrapped error to preserve original cause")
	}
	if errors.Is(wrapped, types.ErrAuthenticationFailed) {
		t.Fatal("expected non-401 response to avoid authentication mapping")
	}

	var compatErr *types.CloudflareCompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected wrapped error to expose CloudflareCompatError")
	}
	if compatErr.Quirk != "response_error" {
		t.Fatalf("expected quirk %q, got %q", "response_error", compatErr.Quirk)
	}
	if compatErr.Cause != cause {
		t.Fatalf("expected cause %v, got %v", cause, compatErr.Cause)
	}
}

// 验证构造入口在错误分支中会保留阶段上下文与基础错误类型。
func TestSessionConstructorsReturnContextualErrors(t *testing.T) {
	tests := []struct {
		name        string
		newInstance func() error
		wantMessage string
	}{
		{
			name: "cloudflare compat layer wraps validation error",
			newInstance: func() error {
				_, err := kernel.NewCloudflareCompatLayer(config.KernelConfig{MTU: 1200})
				return err
			},
			wantMessage: "validate cloudflare config",
		},
		{
			name: "connect ip manager wraps quic build error",
			newInstance: func() error {
				_, err := kernel.NewConnectIPSessionManager(config.KernelConfig{ConnectTimeout: -1 * time.Second})
				return err
			},
			wantMessage: "build quic options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.newInstance()
			if err == nil {
				t.Fatal("expected constructor error")
			}
			if !errors.Is(err, types.ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("expected error to contain %q, got %q", tt.wantMessage, err.Error())
			}
		})
	}
}
