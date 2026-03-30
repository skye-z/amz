package runtime

import "context"

type HealthCheckMode string

const (
	HealthCheckModePassiveProxy HealthCheckMode = "passive_proxy"
	HealthCheckModeActiveTunnel HealthCheckMode = "active_tunnel"
)

type HealthCheckFunc func(context.Context) error

type HealthCheckSpec struct {
	Component string
	Mode      HealthCheckMode
	Check     HealthCheckFunc
}

func (s HealthCheckSpec) Run(ctx context.Context) error {
	if s.Check == nil {
		return nil
	}
	return s.Check(ctx)
}
