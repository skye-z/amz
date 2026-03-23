package types_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/skye-z/amz/types"
)

// 验证基础错误可以被 errors.Is 识别。
func TestCommonErrors(t *testing.T) {
	if !errors.Is(types.ErrInvalidConfig, types.ErrInvalidConfig) {
		t.Fatal("expected ErrInvalidConfig to match itself")
	}
	if !errors.Is(types.ErrUnsupportedMode, types.ErrUnsupportedMode) {
		t.Fatal("expected ErrUnsupportedMode to match itself")
	}
	if !errors.Is(types.ErrNotImplemented, types.ErrNotImplemented) {
		t.Fatal("expected ErrNotImplemented to match itself")
	}
}

// 验证最小脱敏入口会隐藏错误中的敏感字段值。
func TestSanitizeErrorRedactsSensitiveValues(t *testing.T) {
	err := fmt.Errorf(
		"register failed: token=%s private_key=%s device_credentials=%s",
		"tok_live_123456",
		"priv_key_abcdef",
		"cred_payload_xyz",
	)

	masked := types.SanitizeError(err)
	if masked == "" {
		t.Fatal("expected sanitized message")
	}
	for _, secret := range []string{"tok_live_123456", "priv_key_abcdef", "cred_payload_xyz"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("expected secret %q to be redacted, got %q", secret, masked)
		}
	}
	for _, marker := range []string{"token=<redacted>", "private_key=<redacted>", "device_credentials=<redacted>"} {
		if !strings.Contains(masked, marker) {
			t.Fatalf("expected marker %q in %q", marker, masked)
		}
	}
}

// 验证文本脱敏会处理日志中嵌套出现的敏感键值对。
func TestSanitizeTextRedactsNestedSensitiveValues(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
		marker string
	}{
		{
			name:   "endpoint token value",
			input:  "tunnel start: mode=tun endpoint=token=tok_live_123456",
			secret: "tok_live_123456",
			marker: "endpoint=token=<redacted>",
		},
		{
			name:   "json style credentials",
			input:  `register failed: payload={"token":"tok_live_123456","private_key":"priv_key_abcdef","device_credentials":"cred_payload_xyz"}`,
			secret: "tok_live_123456",
			marker: `"token":"<redacted>"`,
		},
		{
			name:   "authorization bearer token",
			input:  "request rejected: Authorization: Bearer tok_live_123456",
			secret: "tok_live_123456",
			marker: "Authorization: Bearer <redacted>",
		},
		{
			name:   "camel case credentials",
			input:  `enroll failed: payload={"privateKey":"priv_key_abcdef","deviceCredentials":"cred_payload_xyz"}`,
			secret: "priv_key_abcdef",
			marker: `"privateKey":"<redacted>"`,
		},
		{
			name:   "api key and refresh token",
			input:  `auth failed: payload={"apiKey":"api_live_123","refreshToken":"refresh_456","licenseKey":"warp_789"}`,
			secret: "api_live_123",
			marker: `"apiKey":"<redacted>"`,
		},
		{
			name:   "password and secret values",
			input:  "proxy auth failed: password=hunter2 secret=shh-123",
			secret: "hunter2",
			marker: "password=<redacted>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := types.SanitizeText(tt.input)
			if strings.Contains(masked, tt.secret) {
				t.Fatalf("expected secret %q to be redacted, got %q", tt.secret, masked)
			}
			if !strings.Contains(masked, tt.marker) {
				t.Fatalf("expected marker %q in %q", tt.marker, masked)
			}
		})
	}
}
