package runtime

import (
	"context"
	"errors"
	"net"

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
)

type socks5Starter interface {
	Start(context.Context) error
	StartWithListener(context.Context, net.Listener) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() internalconfig.Stats
	ListenAddress() string
}

type SOCKS5Runtime struct {
	manager  socks5Starter
	listener net.Listener
	health   HealthCheckSpec
}

func NewSOCKS5Runtime(manager socks5Starter) *SOCKS5Runtime {
	if manager == nil {
		return nil
	}
	return &SOCKS5Runtime{
		manager: manager,
		health: HealthCheckSpec{
			Component: "socks5",
			Mode:      HealthCheckModePassiveProxy,
		},
	}
}

func (r *SOCKS5Runtime) SetListener(listener net.Listener) {
	r.listener = listener
}

func (r *SOCKS5Runtime) Start(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return errors.New("socks5 runtime manager is required")
	}
	if r.listener != nil {
		return r.manager.StartWithListener(ctx, r.listener)
	}
	return r.manager.Start(ctx)
}

func (r *SOCKS5Runtime) Close() error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close()
}

func (r *SOCKS5Runtime) Stop(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Stop(ctx)
}

func (r *SOCKS5Runtime) ListenAddress() string {
	if r == nil || r.manager == nil {
		return ""
	}
	return r.manager.ListenAddress()
}

func (r *SOCKS5Runtime) State() string {
	if r == nil || r.manager == nil {
		return internalconfig.StateStopped
	}
	return r.manager.State()
}

func (r *SOCKS5Runtime) Stats() internalconfig.Stats {
	if r == nil || r.manager == nil {
		return internalconfig.Stats{}
	}
	return r.manager.Stats()
}

func (r *SOCKS5Runtime) HealthCheck(ctx context.Context) error {
	if r == nil {
		return nil
	}
	return r.health.Run(ctx)
}

func (r *SOCKS5Runtime) SetHealthCheck(checker HealthCheckFunc) {
	if r == nil {
		return
	}
	r.health.Check = checker
}

func (r *SOCKS5Runtime) HealthSpec() HealthCheckSpec {
	if r == nil {
		return HealthCheckSpec{}
	}
	return r.health
}

func (r *SOCKS5Runtime) SetFailureReporter(reporter func(failure.Event)) {
	if r == nil {
		return
	}
	if manager, ok := r.manager.(*SOCKS5Manager); ok {
		manager.SetFailureReporter(reporter)
	}
}
