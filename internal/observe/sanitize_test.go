package observe_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/skye-z/amz/internal/observe"
)

func TestSanitizeErrorRedactsSensitiveValues(t *testing.T) {
	err := fmt.Errorf("register failed: token=%s private_key=%s device_credentials=%s", "tok_live_123456", "priv_key_abcdef", "cred_payload_xyz")
	masked := observe.SanitizeError(err)
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

func TestSanitizeTextRedactsNestedSensitiveValues(t *testing.T) {
	masked := observe.SanitizeText(`auth failed: payload={"apiKey":"api_live_123","refreshToken":"refresh_456","licenseKey":"warp_789"}`)
	for _, secret := range []string{"api_live_123", "refresh_456", "warp_789"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("expected secret %q to be redacted, got %q", secret, masked)
		}
	}
	for _, marker := range []string{`"apiKey":"<redacted>"`, `"refreshToken":"<redacted>"`, `"licenseKey":"<redacted>"`} {
		if !strings.Contains(masked, marker) {
			t.Fatalf("expected marker %q in %q", marker, masked)
		}
	}
}
