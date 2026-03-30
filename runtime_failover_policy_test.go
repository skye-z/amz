package amz

import (
	"context"
	"errors"
	"testing"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
)

func TestClassifyRuntimeFailureMapsCloudflareQuirksToFailover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		class  runtimeFailureClass
		action runtimeFailoverAction
	}{
		{
			name:   "unauthorized",
			err:    internalcloudflare.WrapError("connect-stream", internalcloudflare.CloudflareQuirkUnauthorized, internalcloudflare.ErrAuthenticationFailed),
			class:  runtimeFailureClassAuth,
			action: runtimeFailoverActionSwitchEndpoint,
		},
		{
			name:   "protocol mismatch",
			err:    internalcloudflare.WrapError("connect-ip", internalcloudflare.CloudflareQuirkProtocolMismatch, errors.New("bad request")),
			class:  runtimeFailureClassProtocol,
			action: runtimeFailoverActionSwitchEndpoint,
		},
		{
			name:   "rate limited",
			err:    internalcloudflare.WrapError("connect-ip", internalcloudflare.CloudflareQuirkRateLimited, errors.New("429")),
			class:  runtimeFailureClassRateLimited,
			action: runtimeFailoverActionSwitchEndpoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := classifyRuntimeFailure(tt.err)
			if decision.Class != tt.class {
				t.Fatalf("expected class %q, got %q", tt.class, decision.Class)
			}
			if decision.Action != tt.action {
				t.Fatalf("expected action %q, got %q", tt.action, decision.Action)
			}
		})
	}
}

func TestClassifyRuntimeFailureIgnoresCanceledContext(t *testing.T) {
	t.Parallel()

	decision := classifyRuntimeFailure(context.Canceled)
	if decision.Action != runtimeFailoverActionIgnore {
		t.Fatalf("expected ignore action, got %+v", decision)
	}
}

func TestClassifyRuntimeFailureTreatsTunHealthAsSwitchable(t *testing.T) {
	t.Parallel()

	decision := classifyRuntimeFailure(errors.New("tun health check observed no relay traffic"))
	if decision.Class != runtimeFailureClassTunnelHealth {
		t.Fatalf("expected tunnel health class, got %+v", decision)
	}
	if decision.Action != runtimeFailoverActionSwitchEndpoint {
		t.Fatalf("expected switch action, got %+v", decision)
	}
}
