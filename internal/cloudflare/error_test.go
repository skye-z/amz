package cloudflare_test

import (
	"errors"
	"testing"

	"github.com/skye-z/amz/internal/cloudflare"
)

func TestWrapCloudflareError(t *testing.T) {
	wrapped := cloudflare.WrapError("connect-ip", "unauthorized", cloudflare.ErrAuthenticationFailed)
	if wrapped == nil {
		t.Fatal("expected wrapped error")
	}
	if !errors.Is(wrapped, cloudflare.ErrCompat) {
		t.Fatal("expected wrapped error to match ErrCompat")
	}
	if !errors.Is(wrapped, cloudflare.ErrAuthenticationFailed) {
		t.Fatal("expected wrapped error to match ErrAuthenticationFailed")
	}
	var compatErr *cloudflare.CompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected wrapped error to expose CompatError")
	}
	if compatErr.Operation != "connect-ip" || compatErr.Quirk != "unauthorized" || compatErr.Cause != cloudflare.ErrAuthenticationFailed {
		t.Fatalf("unexpected compat error: %+v", compatErr)
	}
}
