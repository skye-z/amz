package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/observe"
)

type tunBootstrap interface {
	Prepare(context.Context) error
	Close() error
}

type BootstrapTUNManager struct {
	mu        sync.Mutex
	cfg       internalconfig.KernelConfig
	state     string
	stats     internalconfig.Stats
	bootstrap tunBootstrap
}

func NewBootstrapTUNManager(cfg *internalconfig.KernelConfig, bootstrap tunBootstrap) (*BootstrapTUNManager, error) {
	if cfg == nil {
		return nil, errors.New("kernel config is required")
	}
	if bootstrap == nil {
		return nil, errors.New("tun bootstrap is required")
	}
	clone := *cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return &BootstrapTUNManager{
		cfg:       clone,
		state:     internalconfig.StateIdle,
		bootstrap: bootstrap,
	}, nil
}

func (t *BootstrapTUNManager) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.state == internalconfig.StateStopped {
		t.mu.Unlock()
		return errors.New("tunnel already stopped")
	}
	if t.state == internalconfig.StateRunning {
		t.mu.Unlock()
		return nil
	}
	t.logf("tunnel start: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	bootstrap := t.bootstrap
	t.mu.Unlock()

	if err := bootstrap.Prepare(ctx); err != nil {
		return err
	}

	t.mu.Lock()
	t.state = internalconfig.StateRunning
	t.stats.StartCount++
	t.mu.Unlock()
	return nil
}

func (t *BootstrapTUNManager) Stop(context.Context) error {
	t.mu.Lock()
	if t.state == internalconfig.StateStopped {
		t.mu.Unlock()
		return nil
	}
	t.logf("tunnel stop: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	bootstrap := t.bootstrap
	t.state = internalconfig.StateStopped
	t.stats.StopCount++
	t.mu.Unlock()

	if bootstrap != nil {
		return bootstrap.Close()
	}
	return nil
}

func (t *BootstrapTUNManager) Close() error { return t.Stop(context.Background()) }

func (t *BootstrapTUNManager) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *BootstrapTUNManager) Stats() internalconfig.Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

func (t *BootstrapTUNManager) logf(format string, args ...any) {
	if t.cfg.Logger == nil {
		return
	}
	original := fmt.Sprintf(format, args...)
	masked := fmt.Sprintf(format, sanitizeBootstrapTunArgs(args)...)
	masked = observe.SanitizeText(masked)
	if masked != original {
		t.cfg.Logger.Printf(masked)
		return
	}
	t.cfg.Logger.Printf(format, args...)
}

func sanitizeBootstrapTunArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	masked := make([]any, len(args))
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			masked[i] = observe.SanitizeText(text)
			continue
		}
		if err, ok := arg.(error); ok {
			masked[i] = observe.SanitizeError(err)
			continue
		}
		masked[i] = arg
	}
	return masked
}
