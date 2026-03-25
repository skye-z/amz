package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/observe"
)

type TunManager struct {
	mu    sync.Mutex
	cfg   internalconfig.KernelConfig
	state string
	stats internalconfig.Stats
}

func NewTunManager(cfg *internalconfig.KernelConfig) (*TunManager, error) {
	if cfg == nil {
		return nil, errors.New("kernel config is required")
	}
	clone := *cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return &TunManager{cfg: clone, state: internalconfig.StateIdle}, nil
}

func (t *TunManager) Start(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == internalconfig.StateStopped {
		return errors.New("tunnel already stopped")
	}
	t.logf("tunnel start: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	t.state = internalconfig.StateRunning
	t.stats.StartCount++
	return nil
}

func (t *TunManager) Stop(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == internalconfig.StateStopped {
		return nil
	}
	t.logf("tunnel stop: mode=%s endpoint=%s", t.cfg.Mode, t.cfg.Endpoint)
	t.state = internalconfig.StateStopped
	t.stats.StopCount++
	return nil
}

func (t *TunManager) Close() error { return t.Stop(context.Background()) }

func (t *TunManager) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *TunManager) Stats() internalconfig.Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

func (t *TunManager) Logger() internalconfig.Logger {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg.Logger
}

func (t *TunManager) logf(format string, args ...any) {
	if t.cfg.Logger == nil {
		return
	}
	original := fmt.Sprintf(format, args...)
	masked := fmt.Sprintf(format, sanitizeTunArgs(args)...)
	masked = observe.SanitizeText(masked)
	if masked != original {
		t.cfg.Logger.Printf(masked)
		return
	}
	t.cfg.Logger.Printf(format, args...)
}

func sanitizeTunArgs(args []any) []any {
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

func NormalizeTUNName(name string) string {
	return strings.TrimSpace(name)
}
