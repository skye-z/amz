package runtime

import (
	"context"
	"errors"
	"net"

	internalconfig "github.com/skye-z/amz/internal/config"
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
}

func NewSOCKS5Runtime(manager socks5Starter) *SOCKS5Runtime {
	if manager == nil {
		return nil
	}
	return &SOCKS5Runtime{manager: manager}
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

func (r *SOCKS5Runtime) SetFailureReporter(reporter func(error)) {
	if r == nil {
		return
	}
	if manager, ok := r.manager.(*SOCKS5Manager); ok {
		manager.SetFailureReporter(reporter)
	}
}
