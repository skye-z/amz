package amz

import (
	"context"
	"sync"
)

type sdkRuntime interface {
	Start(context.Context) error
	Run() error
	Close() error
	Status() Status
	ListenAddress() string
}

// buildSDKRuntime is wired by the internal runtime package in the SDK v1
// implementation. Keeping it as a package variable lets the root package stay
// stable while internal/runtime evolves.
var buildSDKRuntime = func(Options) (sdkRuntime, error) {
	return &noopRuntime{}, nil
}

type Client struct {
	mu      sync.Mutex
	opts    Options
	runtime sdkRuntime
	closed  bool
}

func NewClient(opts Options) (*Client, error) {
	normalized := opts.normalized()
	if !normalized.HTTP.Enabled && !normalized.SOCKS5.Enabled && !normalized.TUN.Enabled {
		logEvent(normalized.Logger, "client", "new.failed",
			field("reason", ErrNoRuntimeEnabled),
			field("http_enabled", normalized.HTTP.Enabled),
			field("socks5_enabled", normalized.SOCKS5.Enabled),
			field("tun_enabled", normalized.TUN.Enabled),
		)
		return nil, ErrNoRuntimeEnabled
	}
	runtime, err := buildSDKRuntime(normalized)
	if err != nil {
		logEvent(normalized.Logger, "client", "new.failed",
			field("error", err),
			field("http_enabled", normalized.HTTP.Enabled),
			field("socks5_enabled", normalized.SOCKS5.Enabled),
			field("tun_enabled", normalized.TUN.Enabled),
			field("listen_address", normalized.Listen.Address),
		)
		return nil, err
	}
	logEvent(normalized.Logger, "client", "new.success",
		field("http_enabled", normalized.HTTP.Enabled),
		field("socks5_enabled", normalized.SOCKS5.Enabled),
		field("tun_enabled", normalized.TUN.Enabled),
		field("listen_address", normalized.Listen.Address),
	)
	return &Client{
		opts:    normalized,
		runtime: runtime,
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		logEvent(c.opts.Logger, "client", "start.failed", field("error", ErrClientClosed))
		return ErrClientClosed
	}
	runtime := c.runtime
	logger := c.opts.Logger
	c.mu.Unlock()

	logEvent(logger, "client", "start.begin")
	if err := runtime.Start(ctx); err != nil {
		logEvent(logger, "client", "start.failed", field("error", err))
		return err
	}
	logEvent(logger, "client", "start.success",
		field("listen_address", c.ListenAddress()),
		field("running", c.Status().Running),
	)
	return nil
}

func (c *Client) Run() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		logEvent(c.opts.Logger, "client", "run.failed", field("error", ErrClientClosed))
		return ErrClientClosed
	}
	runtime := c.runtime
	logger := c.opts.Logger
	c.mu.Unlock()

	logEvent(logger, "client", "run.begin")
	if err := runtime.Run(); err != nil {
		logEvent(logger, "client", "run.failed", field("error", err))
		return err
	}
	logEvent(logger, "client", "run.success")
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		logEvent(c.opts.Logger, "client", "close.skipped", field("reason", "already_closed"))
		return nil
	}
	c.closed = true
	runtime := c.runtime
	logger := c.opts.Logger
	c.mu.Unlock()

	logEvent(logger, "client", "close.begin")
	if err := runtime.Close(); err != nil {
		logEvent(logger, "client", "close.failed", field("error", err))
		return err
	}
	logEvent(logger, "client", "close.success")
	return nil
}

func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime.Status()
}

func (c *Client) ListenAddress() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime.ListenAddress()
}

type noopRuntime struct {
	status Status
}

func (n *noopRuntime) Start(context.Context) error { return nil }
func (n *noopRuntime) Run() error                  { return nil }
func (n *noopRuntime) Close() error                { return nil }
func (n *noopRuntime) Status() Status              { return n.status }
func (n *noopRuntime) ListenAddress() string       { return n.status.ListenAddress }
