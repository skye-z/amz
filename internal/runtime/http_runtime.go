package runtime

import (
	"context"
	"errors"
	"net"

	internalconfig "github.com/skye-z/amz/internal/config"
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
}

func NewHTTPRuntime(manager httpStarter) *HTTPRuntime {
	if manager == nil {
		return nil
	}
	return &HTTPRuntime{manager: manager}
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

func (r *HTTPRuntime) SetFailureReporter(reporter func(error)) {
	if r == nil {
		return
	}
	if manager, ok := r.manager.(*HTTPManager); ok {
		manager.SetFailureReporter(reporter)
	}
}
