package observe

import (
	"fmt"
	"strings"
	"testing"
)

type recordLogger struct {
	entries []string
}

func (l *recordLogger) Printf(format string, args ...any) {
	l.entries = append(l.entries, fmt.Sprintf(format, args...))
}

func TestLogfUsesInjectedLogger(t *testing.T) {
	logger := &recordLogger{}

	Logf(logger, "tunnel start: mode=%s endpoint=%s", "tun", "162.159.198.1:443")

	if len(logger.entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(logger.entries))
	}
	if logger.entries[0] != "tunnel start: mode=tun endpoint=162.159.198.1:443" {
		t.Fatalf("expected stable formatted log entry, got %q", logger.entries[0])
	}
}

func TestLogfRedactsSensitiveValues(t *testing.T) {
	logger := &recordLogger{}

	Logf(logger, "tunnel start: mode=%s endpoint=%s err=%v", "tun", "token=tok_live_123456", fmt.Errorf("register failed: private_key=priv_key_abcdef"))

	if len(logger.entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	for _, secret := range []string{"tok_live_123456", "priv_key_abcdef"} {
		if strings.Contains(entry, secret) {
			t.Fatalf("expected secret %q to be redacted, got %q", secret, entry)
		}
	}
	if got := logger.entries[0]; got != "tunnel start: mode=tun endpoint=token=<redacted> err=register failed: private_key=<redacted>" {
		t.Fatalf("expected redacted log entry, got %q", got)
	}
}

func TestLogfSilentWithoutLogger(t *testing.T) {
	Logf(nil, "ignored %s", "value")
}
