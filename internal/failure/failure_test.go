package failure

import (
	"context"
	"errors"
	"testing"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
)

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
			event: Event{Component: ComponentSession, Err: internalcloudflare.WrapError("connect-ip", internalcloudflare.CloudflareQuirkProtocolMismatch, errors.New("bad request"))},
			class: ClassProtocol,
		},
		{
			name:  "rate limited",
			event: Event{Component: ComponentSession, Err: internalcloudflare.WrapError("connect-ip", internalcloudflare.CloudflareQuirkRateLimited, errors.New("429"))},
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

	if ok := bus.Publish(Event{Component: ComponentHTTP, Endpoint: "a:443", Err: errors.New("boom")}); !ok {
		t.Fatal("expected publish success")
	}
	event := <-done
	if event.Endpoint != "a:443" {
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
	if ok := bus.Publish(Event{Endpoint: "first"}); !ok {
		t.Fatal("expected first publish success")
	}
	if ok := bus.Publish(Event{Endpoint: "second"}); !ok {
		t.Fatal("expected second publish success even when buffer is full")
	}
	gotFirst := <-handled
	gotSecond := <-handled
	if gotFirst.Endpoint == "" || gotSecond.Endpoint == "" {
		t.Fatalf("expected handled events, got %+v %+v", gotFirst, gotSecond)
	}
	bus.Close()
	if ok := bus.Publish(Event{Endpoint: "third"}); ok {
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
	if decision := Classify(Event{Err: internalcloudflare.WrapError("connect-ip", "mystery", errors.New("boom"))}); decision.Class != ClassTransport || decision.Action != ActionSwitchEndpoint {
		t.Fatalf("expected default cloudflare transport decision, got %+v", decision)
	}
}
