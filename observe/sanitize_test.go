package observe

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeArgsRedactsErrorValues(t *testing.T) {
	masked := SanitizeArgs([]any{
		errors.New("register failed: token=tok_live_123456 private_key=priv_key_abcdef"),
	})

	if len(masked) != 1 {
		t.Fatalf("expected one masked argument, got %d", len(masked))
	}

	text, ok := masked[0].(string)
	if !ok {
		t.Fatalf("expected masked error to become string, got %T", masked[0])
	}

	for _, secret := range []string{"tok_live_123456", "priv_key_abcdef"} {
		if strings.Contains(text, secret) {
			t.Fatalf("expected secret %q to be redacted, got %q", secret, text)
		}
	}

	for _, marker := range []string{"token=<redacted>", "private_key=<redacted>"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("expected marker %q in %q", marker, text)
		}
	}
}
