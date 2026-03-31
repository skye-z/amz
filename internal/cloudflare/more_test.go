package cloudflare

import (
	"errors"
	"testing"
)

func TestCompatErrorFormattingVariants(t *testing.T) {
	if got := (*CompatError)(nil).Error(); got != ErrCompat.Error() {
		t.Fatalf("expected nil compat error string %q, got %q", ErrCompat.Error(), got)
	}
	err := &CompatError{Operation: "connect-stream", Quirk: "protocol_error"}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
	if !errors.Is(err, ErrCompat) {
		t.Fatal("expected CompatError to match ErrCompat")
	}
	if err.Unwrap() != nil {
		t.Fatal("expected nil unwrap when cause absent")
	}
}

func TestWrapErrorWithNilCause(t *testing.T) {
	wrapped := WrapError("connect-ip", "missing_datagrams", nil)
	var compatErr *CompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected wrapped compat error")
	}
	if compatErr.Operation != "connect-ip" || compatErr.Quirk != "missing_datagrams" {
		t.Fatalf("unexpected compat error: %+v", compatErr)
	}
	if compatErr.Unwrap() != nil {
		t.Fatal("expected nil cause unwrap")
	}
}

func TestDefaultQuirksAndCompatErrorHelpers(t *testing.T) {
	quirks := DefaultQuirks()
	if quirks.Name == "" || !quirks.UseCFConnectIP || !quirks.RequireDatagrams || !quirks.MapUnauthorizedToAuthError {
		t.Fatalf("unexpected default quirks: %+v", quirks)
	}

	var nilCompat *CompatError
	if nilCompat.Unwrap() != nil {
		t.Fatal("expected nil unwrap on nil compat error")
	}
	if !(&CompatError{}).Is(ErrCompat) {
		t.Fatal("expected CompatError.Is to match ErrCompat")
	}
}
