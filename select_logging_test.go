package amz

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/discovery"
)

func TestLoggingProberEmitsPerCandidateDiagnostics(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	base := discovery.NewStaticProber(map[string]discovery.ProbeResult{
		"162.159.198.2:443": {
			Address:     "162.159.198.2:443",
			Latency:     5 * time.Millisecond,
			Available:   true,
			WarpEnabled: true,
		},
	})

	wrapped := newLoggingProber(logger, base)
	results := wrapped.Probe([]discovery.Candidate{
		{Address: "162.159.198.2:443", Source: discovery.SourceFixed},
	})
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}

	output := logger.String()
	for _, want := range []string{
		"[SELECT]",
		"probing candidate",
		"probe finished",
		"candidate=\"162.159.198.2:443\"",
		"source=\"fixed\"",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestLoggingWarpStatusCheckerEmitsDiagnostics(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	base := discovery.WarpStatusFunc(func(context.Context, discovery.Candidate) (bool, error) {
		return true, nil
	})

	wrapped := newLoggingWarpStatusChecker(logger, base)
	ok, err := wrapped.CheckWarp(context.Background(), discovery.Candidate{
		Address: "162.159.198.2:443",
		Source:  discovery.SourceFixed,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatal("expected warp check success")
	}

	output := logger.String()
	for _, want := range []string{
		"[SELECT]",
		"checking warp availability",
		"warp availability confirmed",
		"candidate=\"162.159.198.2:443\"",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}
