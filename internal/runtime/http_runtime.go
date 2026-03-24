package runtime

import (
	"context"
	"errors"
	"net"

	httpproxy "github.com/skye-z/amz/proxy/http"
	"github.com/skye-z/amz/types"
)

type httpStarter interface {
	Start(context.Context) error
	StartWithListener(context.Context, net.Listener) error
	Stop(context.Context) error
	Close() error
	State() string
	Stats() types.Stats
	ListenAddress() string
}

type HTTPRuntime struct {
	manager  httpStarter
	listener net.Listener
}

func NewHTTPRuntime(manager *httpproxy.Manager) *HTTPRuntime {
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
		return types.StateStopped
	}
	return r.manager.State()
}

func (r *HTTPRuntime) Stats() types.Stats {
	if r == nil || r.manager == nil {
		return types.Stats{}
	}
	return r.manager.Stats()
}
