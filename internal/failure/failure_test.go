package failure

import (
	"context"
	"errors"
	"testing"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
)

const failureConnectIPOperation = "connect-ip"

func TestClassifyMapsCloudflareQuirksToSwitchEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event Event
		class Class
	}{
		{
			name:  "unauthorized",
			event: Event{Component: ComponentHTTP, Err: internalcloudflare.WrapError("connect-stream", internalcloudflare.CloudflareQuirkUnauthorized, internalcloudflare.ErrAuthenticationFailed)},
			class: ClassAuth,
		},
		{
			name:  "protocol mismatch",
			event: Event{Component: ComponentSession, Err: internalcloudflare.WrapError(failureConnectIPOperation, internalcloudflare.CloudflareQuirkProtocolMismatch, errors.New("bad request"))},
			class: ClassProtocol,
		},
		{
			name:  "rate limited",
			event: Event{Component: ComponentSession, Err: internalcloudflare.WrapError(failureConnectIPOperation, internalcloudflare.CloudflareQuirkRateLimited, errors.New("429"))},
			class: ClassRateLimited,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Classify(tt.event)
			if decision.Class != tt.class {
				t.Fatalf("expected class %q, got %q", tt.class, decision.Class)
			}
			if decision.Action != ActionSwitchEndpoint {
				t.Fatalf("expected switch action, got %+v", decision)
			}
		})
	}
}

func TestClassifyIgnoresCanceledContext(t *testing.T) {
	t.Parallel()

	decision := Classify(Event{Component: ComponentHTTP, Err: context.Canceled})
	if decision.Action != ActionIgnore {
		t.Fatalf("expected ignore action, got %+v", decision)
	}
}

func TestClassifyTreatsTunHealthAsSwitchable(t *testing.T) {
	t.Parallel()

	decision := Classify(Event{Component: ComponentTUN, Err: errors.New("tun health check observed no relay traffic")})
	if decision.Class != ClassTunnelHealth {
		t.Fatalf("expected tun health class, got %+v", decision)
	}
	if decision.Action != ActionSwitchEndpoint {
		t.Fatalf("expected switch action, got %+v", decision)
	}
}

func TestBusDeliversPublishedEvents(t *testing.T) {
	t.Parallel()

	done := make(chan Event, 1)
	bus := NewBus(1, func(event Event) {
		done <- event
	})
	defer bus.Close()

	if !bus.Publish(Event{Component: ComponentHTTP, Endpoint: "a:443", Err: errors.New("boom")}) {
		t.Fatal("expected publish success")
	}
	if event := <-done; event.Endpoint != "a:443" {
		t.Fatalf("expected endpoint a:443, got %+v", event)
	}
}

func TestClassifyTreatsTransportTimeoutAsRetryCurrent(t *testing.T) {
	t.Parallel()

	decision := Classify(Event{Component: ComponentHTTP, Err: context.DeadlineExceeded})
	if decision.Class != ClassTransport {
		t.Fatalf("expected transport class, got %+v", decision)
	}
	if decision.Action != ActionRetryCurrent {
		t.Fatalf("expected retry_current action, got %+v", decision)
	}
}

func TestFailureBusNilClosedAndAsyncBranches(t *testing.T) {
	t.Parallel()

	var nilBus *Bus
	if nilBus.Publish(Event{}) {
		t.Fatal("expected nil bus publish to return false")
	}
	nilBus.Close()

	handled := make(chan Event, 2)
	bus := NewBus(1, func(event Event) {
		handled <- event
	})
	if !bus.Publish(Event{Endpoint: "first"}) {
		t.Fatal("expected first publish success")
	}
	if !bus.Publish(Event{Endpoint: "second"}) {
		t.Fatal("expected second publish success even when buffer is full")
	}
	events := []Event{<-handled, <-handled}
	if events[0].Endpoint == "" || events[1].Endpoint == "" {
		t.Fatalf("expected handled events, got %+v %+v", events[0], events[1])
	}
	bus.Close()
	if bus.Publish(Event{Endpoint: "third"}) {
		t.Fatal("expected publish to fail after close")
	}
	bus.Close()
}

func TestClassifyAdditionalBranches(t *testing.T) {
	t.Parallel()

	if decision := Classify(Event{}); decision.Action != ActionIgnore {
		t.Fatalf("expected nil error to be ignored, got %+v", decision)
	}
	if decision := Classify(Event{Err: errors.New("authentication failed")}); decision.Class != ClassAuth || decision.Action != ActionSwitchEndpoint {
		t.Fatalf("expected auth switch decision, got %+v", decision)
	}
	if decision := Classify(Event{Err: errors.New("bad request")}); decision.Class != ClassProtocol || decision.Action != ActionSwitchEndpoint {
		t.Fatalf("expected protocol switch decision, got %+v", decision)
	}
	if decision := Classify(Event{Err: errors.New("eof")}); decision.Class != ClassTransport || decision.Action != ActionRetryCurrent {
		t.Fatalf("expected transport retry decision, got %+v", decision)
	}
	if decision := Classify(Event{Err: internalcloudflare.WrapError(failureConnectIPOperation, "mystery", errors.New("boom"))}); decision.Class != ClassTransport || decision.Action != ActionSwitchEndpoint {
		t.Fatalf("expected default cloudflare transport decision, got %+v", decision)
	}
}
