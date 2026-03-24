package runtime

import (
	"context"

	"github.com/skye-z/amz/types"
)

type TUNRuntime struct {
	runtime types.Tunnel
}

func NewTUNRuntime(runtime types.Tunnel) *TUNRuntime {
	if runtime == nil {
		return nil
	}
	return &TUNRuntime{runtime: runtime}
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

func (r *TUNRuntime) State() string {
	if r == nil || r.runtime == nil {
		return types.StateStopped
	}
	return r.runtime.State()
}

func (r *TUNRuntime) Stats() types.Stats {
	if r == nil || r.runtime == nil {
		return types.Stats{}
	}
	return r.runtime.Stats()
}
