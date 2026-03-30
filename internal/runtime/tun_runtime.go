package runtime

import (
	"context"

	internalconfig "github.com/skye-z/amz/internal/config"
)

type TUNRuntime struct {
	runtime     internalconfig.Tunnel
	healthCheck func(context.Context) error
	health      HealthCheckSpec
}

func NewTUNRuntime(runtime internalconfig.Tunnel) *TUNRuntime {
	if runtime == nil {
		return nil
	}
	return &TUNRuntime{
		runtime: runtime,
		health: HealthCheckSpec{
			Component: "tun",
			Mode:      HealthCheckModeActiveTunnel,
		},
	}
}

func NewTUNRuntimeWithHealth(runtime internalconfig.Tunnel, healthCheck func(context.Context) error) *TUNRuntime {
	if runtime == nil {
		return nil
	}
	return &TUNRuntime{
		runtime:     runtime,
		healthCheck: healthCheck,
		health: HealthCheckSpec{
			Component: "tun",
			Mode:      HealthCheckModeActiveTunnel,
			Check:     healthCheck,
		},
	}
}

func (r *TUNRuntime) Start(ctx context.Context) error {
	if r == nil || r.runtime == nil {
		return nil
	}
	return r.runtime.Start(ctx)
}

func (r *TUNRuntime) Close() error {
	if r == nil || r.runtime == nil {
		return nil
	}
	return r.runtime.Close()
}

func (r *TUNRuntime) Stop(ctx context.Context) error {
	if r == nil || r.runtime == nil {
		return nil
	}
	return r.runtime.Stop(ctx)
}

func (r *TUNRuntime) HealthCheck(ctx context.Context) error {
	if r == nil || r.runtime == nil {
		return nil
	}
	return r.health.Run(ctx)
}

func (r *TUNRuntime) SetHealthCheck(checker HealthCheckFunc) {
	if r == nil {
		return
	}
	r.healthCheck = checker
	r.health.Check = checker
}

func (r *TUNRuntime) HealthSpec() HealthCheckSpec {
	if r == nil {
		return HealthCheckSpec{}
	}
	return r.health
}

func (r *TUNRuntime) State() string {
	if r == nil || r.runtime == nil {
		return internalconfig.StateStopped
	}
	return r.runtime.State()
}

func (r *TUNRuntime) Stats() internalconfig.Stats {
	if r == nil || r.runtime == nil {
		return internalconfig.Stats{}
	}
	return r.runtime.Stats()
}
