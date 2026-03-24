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
		return nil, ErrNoRuntimeEnabled
	}
	runtime, err := buildSDKRuntime(normalized)
	if err != nil {
		return nil, err
	}
	return &Client{
		opts:    normalized,
		runtime: runtime,
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClientClosed
	}
	return c.runtime.Start(ctx)
}

func (c *Client) Run() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClientClosed
	}
	return c.runtime.Run()
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.runtime.Close()
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
