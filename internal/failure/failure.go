package failure

import (
	"context"
	"errors"
	"strings"
	"sync"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
)

type Component string

const (
	ComponentUnknown Component = "unknown"
	ComponentHTTP    Component = "http"
	ComponentSOCKS5  Component = "socks5"
	ComponentTUN     Component = "tun"
	ComponentSession Component = "session"
)

type Class string
type Action string

const (
	ClassUnknown      Class = "unknown"
	ClassAuth         Class = "auth"
	ClassProtocol     Class = "protocol"
	ClassRateLimited  Class = "rate_limited"
	ClassRoute        Class = "route"
	ClassTransport    Class = "transport"
	ClassTunnelHealth Class = "tun_health"
	ClassCanceled     Class = "canceled"

	ActionIgnore         Action = "ignore"
	ActionRetryCurrent   Action = "retry_current"
	ActionSwitchEndpoint Action = "switch_endpoint"
)

type Event struct {
	Component Component
	Operation string
	Endpoint  string
	Err       error
}

type Decision struct {
	Class  Class
	Action Action
	Reason string
}

func Classify(event Event) Decision {
	err := event.Err
	if err == nil {
		return Decision{Class: ClassUnknown, Action: ActionIgnore, Reason: "nil"}
	}
	if errors.Is(err, context.Canceled) {
		return Decision{Class: ClassCanceled, Action: ActionIgnore, Reason: "context_canceled"}
	}

	var compatErr *internalcloudflare.CompatError
	if errors.As(err, &compatErr) {
		switch compatErr.Quirk {
		case internalcloudflare.CloudflareQuirkUnauthorized:
			return Decision{Class: ClassAuth, Action: ActionSwitchEndpoint, Reason: compatErr.Quirk}
		case internalcloudflare.CloudflareQuirkProtocolMismatch, internalcloudflare.CloudflareQuirkProtocolError, internalcloudflare.CloudflareQuirkMissingDatagrams, internalcloudflare.CloudflareQuirkMissingExtendedConnect:
			return Decision{Class: ClassProtocol, Action: ActionSwitchEndpoint, Reason: compatErr.Quirk}
		case internalcloudflare.CloudflareQuirkRateLimited:
			return Decision{Class: ClassRateLimited, Action: ActionSwitchEndpoint, Reason: compatErr.Quirk}
		case internalcloudflare.CloudflareQuirkRouteUnavailable:
			return Decision{Class: ClassRoute, Action: ActionSwitchEndpoint, Reason: compatErr.Quirk}
		default:
			return Decision{Class: ClassTransport, Action: ActionSwitchEndpoint, Reason: compatErr.Quirk}
		}
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "unauthorized"), strings.Contains(message, "authentication failed"), strings.Contains(message, "forbidden"):
		return Decision{Class: ClassAuth, Action: ActionSwitchEndpoint, Reason: "message_auth"}
	case strings.Contains(message, "protocol mismatch"), strings.Contains(message, "bad request"):
		return Decision{Class: ClassProtocol, Action: ActionSwitchEndpoint, Reason: "message_protocol"}
	case strings.Contains(message, "tun health check"):
		return Decision{Class: ClassTunnelHealth, Action: ActionSwitchEndpoint, Reason: "tun_health"}
	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(message, "timeout"),
		strings.Contains(message, "eof"),
		strings.Contains(message, "connect-ip ready"),
		strings.Contains(message, "connect stream"),
		strings.Contains(message, "upstream"),
		strings.Contains(message, "dial quic"):
		return Decision{Class: ClassTransport, Action: ActionRetryCurrent, Reason: "transport"}
	default:
		return Decision{Class: ClassUnknown, Action: ActionRetryCurrent, Reason: "unknown"}
	}
}

type Bus struct {
	ch      chan Event
	handler func(Event)
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
}

func NewBus(buffer int, handler func(Event)) *Bus {
	if buffer <= 0 {
		buffer = 1
	}
	b := &Bus{
		ch:      make(chan Event, buffer),
		handler: handler,
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for event := range b.ch {
			if b.handler != nil {
				b.handler(event)
			}
		}
	}()
	return b
}

func (b *Bus) Publish(event Event) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	select {
	case b.ch <- event:
		return true
	default:
		go func() { b.ch <- event }()
		return true
	}
}

func (b *Bus) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	close(b.ch)
	b.mu.Unlock()
	b.wg.Wait()
}
