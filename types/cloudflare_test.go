package types_test

import (
	"errors"
	"testing"

	"github.com/skye-z/amz/types"
)

// 验证兼容层错误会保留操作、场景与底层错误。
func TestWrapCloudflareError(t *testing.T) {
	wrapped := types.WrapCloudflareError("connect-ip", "unauthorized", types.ErrAuthenticationFailed)

	if wrapped == nil {
		t.Fatal("expected wrapped error")
	}
	if !errors.Is(wrapped, types.ErrCloudflareCompat) {
		t.Fatal("expected wrapped error to match ErrCloudflareCompat")
	}
	if !errors.Is(wrapped, types.ErrAuthenticationFailed) {
		t.Fatal("expected wrapped error to match ErrAuthenticationFailed")
	}

	var compatErr *types.CloudflareCompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected wrapped error to expose CloudflareCompatError")
	}
	if compatErr.Operation != "connect-ip" {
		t.Fatalf("expected operation %q, got %q", "connect-ip", compatErr.Operation)
	}
	if compatErr.Quirk != "unauthorized" {
		t.Fatalf("expected quirk %q, got %q", "unauthorized", compatErr.Quirk)
	}
	if compatErr.Cause != types.ErrAuthenticationFailed {
		t.Fatalf("expected cause %v, got %v", types.ErrAuthenticationFailed, compatErr.Cause)
	}
}
