package runtime

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var errNoRuntimeConfigured = errors.New("at least one runtime must be configured")

type Status struct {
	Running       bool
	ListenAddress string
	HTTPEnabled   bool
	SOCKS5Enabled bool
	TUNEnabled    bool
}

type ClientRuntimeOptions struct {
	ListenAddress string
	HTTP          *HTTPRuntime
	SOCKS5        *SOCKS5Runtime
	TUN           *TUNRuntime
}

type ClientRuntime struct {
	mu       sync.Mutex
	http     *HTTPRuntime
	socks5   *SOCKS5Runtime
	tun      *TUNRuntime
	mux      *MuxListener
	listen   string
	running  bool
	closed   bool
	waitCh   chan struct{}
	waitOnce sync.Once
}

func NewClientRuntime(opts ClientRuntimeOptions) (*ClientRuntime, error) {
	if opts.HTTP == nil && opts.SOCKS5 == nil && opts.TUN == nil {
		return nil, errNoRuntimeConfigured
	}
	return &ClientRuntime{
		http:   opts.HTTP,
		socks5: opts.SOCKS5,
		tun:    opts.TUN,
		listen: resolvedListenAddress(opts),
		waitCh: make(chan struct{}),
	}, nil
}

func (r *ClientRuntime) Start(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("client runtime already closed")
	}
	if r.running {
		r.mu.Unlock()
		return nil
	}
	if r.http != nil && r.socks5 != nil {
		mux, err := ListenMux(r.listen)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		r.mux = mux
		r.listen = mux.ListenAddress()
		r.http.SetListener(mux.HTTPListener())
		r.socks5.SetListener(mux.SOCKS5Listener())
	}
	httpRuntime := r.http
	socksRuntime := r.socks5
	tunRuntime := r.tun
	mux := r.mux
	r.mu.Unlock()

	started := make([]func() error, 0, 3)
	if httpRuntime != nil {
		if err := httpRuntime.Start(ctx); err != nil {
			if mux != nil {
				_ = mux.Close()
			}
			return err
		}
		started = append(started, httpRuntime.Close)
	}
	if socksRuntime != nil {
		if err := socksRuntime.Start(ctx); err != nil {
			stopClosers(started)
			if mux != nil {
				_ = mux.Close()
			}
			return err
		}
		started = append(started, socksRuntime.Close)
	}
	if tunRuntime != nil {
		if err := tunRuntime.Start(ctx); err != nil {
			stopClosers(started)
			if mux != nil {
				_ = mux.Close()
			}
			return err
		}
		started = append(started, tunRuntime.Close)
	}

	r.mu.Lock()
	r.running = true
	if mux == nil {
		r.listen = resolvedRuntimeListenAddress(httpRuntime, socksRuntime)
	}
	r.mu.Unlock()
	return nil
}

func (r *ClientRuntime) Run() error {
	if err := r.Start(context.Background()); err != nil {
		return err
	}
	<-r.waitCh
	return nil
}

func (r *ClientRuntime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.running = false
	httpRuntime := r.http
	socksRuntime := r.socks5
	tunRuntime := r.tun
	mux := r.mux
	r.mux = nil
	r.mu.Unlock()

	var errs []error
	if tunRuntime != nil {
		if err := tunRuntime.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if socksRuntime != nil {
		if err := socksRuntime.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if httpRuntime != nil {
		if err := httpRuntime.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if mux != nil {
		if err := mux.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	r.waitOnce.Do(func() {
		close(r.waitCh)
	})
	return errors.Join(errs...)
}

func (r *ClientRuntime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{
		Running:       r.running,
		ListenAddress: r.listen,
		HTTPEnabled:   r.http != nil,
		SOCKS5Enabled: r.socks5 != nil,
		TUNEnabled:    r.tun != nil,
	}
}

func (r *ClientRuntime) ListenAddress() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listen
}

func resolvedListenAddress(opts ClientRuntimeOptions) string {
	if strings.TrimSpace(opts.ListenAddress) != "" {
		return opts.ListenAddress
	}
	return resolvedRuntimeListenAddress(opts.HTTP, opts.SOCKS5)
}

func resolvedRuntimeListenAddress(httpRuntime *HTTPRuntime, socksRuntime *SOCKS5Runtime) string {
	if httpRuntime != nil && strings.TrimSpace(httpRuntime.ListenAddress()) != "" {
		return httpRuntime.ListenAddress()
	}
	if socksRuntime != nil && strings.TrimSpace(socksRuntime.ListenAddress()) != "" {
		return socksRuntime.ListenAddress()
	}
	return ""
}

func stopClosers(closers []func() error) {
	for i := len(closers) - 1; i >= 0; i-- {
		_ = closers[i]()
	}
}
