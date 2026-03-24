package tun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

type Runtime struct {
	mu    sync.Mutex
	cfg   config.KernelConfig
	state string
	stats types.Stats
}

type Tunnel = Runtime

func NewRuntime(cfg *config.KernelConfig) (*Runtime, error) {
	if cfg == nil {
		return nil, errors.New("kernel config is required")
	}
	clone := *cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return &Runtime{
		cfg:   clone,
		state: types.StateIdle,
	}, nil
}

func NewTunnel(cfg *config.KernelConfig) (*Runtime, error) {
	return NewRuntime(cfg)
}

func (t *Runtime) Start(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == types.StateStopped {
		return errors.New("tunnel already stopped")
	}
	t.logf("tunnel start: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	t.state = types.StateRunning
	t.stats.StartCount++
	return nil
}

func (t *Runtime) Stop(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == types.StateStopped {
		return nil
	}
	t.logf("tunnel stop: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	t.state = types.StateStopped
	t.stats.StopCount++
	return nil
}

func (t *Runtime) Close() error {
	return t.Stop(context.Background())
}

func (t *Runtime) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *Runtime) Stats() types.Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

func (t *Runtime) Logger() config.Logger {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg.Logger
}

func (t *Runtime) logf(format string, args ...any) {
	if t.cfg.Logger == nil {
		return
	}
	original := fmt.Sprintf(format, args...)
	masked := fmt.Sprintf(format, sanitizeArgs(args)...)
	masked = types.SanitizeText(masked)
	if masked != original {
		t.cfg.Logger.Printf(masked)
		return
	}
	t.cfg.Logger.Printf(format, args...)
}

func sanitizeArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	masked := make([]any, len(args))
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			masked[i] = types.SanitizeText(text)
			continue
		}
		if err, ok := arg.(error); ok {
			masked[i] = types.SanitizeError(err)
			continue
		}
		masked[i] = arg
	}
	return masked
}

func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}
