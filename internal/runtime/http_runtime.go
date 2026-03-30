package runtime

import (
	"context"
	"errors"
	"net"

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
)

type httpStarter interface {
	Start(context.Context) error
	StartWithListener(context.Context, net.Listener) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() internalconfig.Stats
	ListenAddress() string
}

type HTTPRuntime struct {
	manager  httpStarter
	listener net.Listener
	health   HealthCheckSpec
}

func NewHTTPRuntime(manager httpStarter) *HTTPRuntime {
	if manager == nil {
		return nil
	}
	return &HTTPRuntime{
		manager: manager,
		health: HealthCheckSpec{
			Component: "http",
			Mode:      HealthCheckModePassiveProxy,
		},
	}
}

func (r *HTTPRuntime) SetListener(listener net.Listener) {
	r.listener = listener
}

func (r *HTTPRuntime) Start(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return errors.New("http runtime manager is required")
	}
	if r.listener != nil {
		return r.manager.StartWithListener(ctx, r.listener)
	}
	return r.manager.Start(ctx)
}

func (r *HTTPRuntime) Close() error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close()
}

func (r *HTTPRuntime) Stop(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Stop(ctx)
}

func (r *HTTPRuntime) ListenAddress() string {
	if r == nil || r.manager == nil {
		return ""
	}
	return r.manager.ListenAddress()
}

func (r *HTTPRuntime) State() string {
	if r == nil || r.manager == nil {
		return internalconfig.StateStopped
	}
	return r.manager.State()
}

func (r *HTTPRuntime) Stats() internalconfig.Stats {
	if r == nil || r.manager == nil {
		return internalconfig.Stats{}
	}
	return r.manager.Stats()
}

func (r *HTTPRuntime) HealthCheck(ctx context.Context) error {
	if r == nil {
		return nil
	}
	return r.health.Run(ctx)
}

func (r *HTTPRuntime) SetHealthCheck(checker HealthCheckFunc) {
	if r == nil {
		return
	}
	r.health.Check = checker
}

func (r *HTTPRuntime) HealthSpec() HealthCheckSpec {
	if r == nil {
		return HealthCheckSpec{}
	}
	return r.health
}

func (r *HTTPRuntime) SetFailureReporter(reporter func(failure.Event)) {
	if r == nil {
		return
	}
	if manager, ok := r.manager.(*HTTPManager); ok {
		manager.SetFailureReporter(reporter)
	}
}
