package discovery

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/testkit"
)

const localProbeAddress443 = testkit.LocalhostIPv4 + ":443"

func TestRealProberUsesConfiguredConcurrencyAndPerCandidateTimeout(t *testing.T) {
	t.Parallel()

	var current int32
	var maxConcurrent int32
	dialer := DialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		active := atomic.AddInt32(&current, 1)
		for {
			seen := atomic.LoadInt32(&maxConcurrent)
			if active <= seen || atomic.CompareAndSwapInt32(&maxConcurrent, seen, active) {
				break
			}
		}
		defer atomic.AddInt32(&current, -1)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	prober := NewRealProber(time.Second,
		WithProbeDialer(dialer),
		WithProbeConcurrency(30),
		WithProbeBatchTimeout(3*time.Second),
	)

	candidates := make([]Candidate, 35)
	for i := range candidates {
		candidates[i] = Candidate{Address: localProbeAddress443}
	}

	started := time.Now()
	results := prober.Probe(candidates)
	elapsed := time.Since(started)

	if len(results) != len(candidates) {
		t.Fatalf("expected %d results, got %d", len(candidates), len(results))
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("expected concurrent probing to finish within 2.5s, got %s", elapsed)
	}
	if atomic.LoadInt32(&maxConcurrent) < 20 {
		t.Fatalf("expected substantial concurrency, got max=%d", maxConcurrent)
	}
}

func TestRealProberStopsWhenBatchTimeoutExpires(t *testing.T) {
	t.Parallel()

	checker := WarpStatusFunc(func(ctx context.Context, candidate Candidate) (bool, error) {
		<-ctx.Done()
		return false, ctx.Err()
	})

	prober := NewRealProber(5*time.Second,
		WithProbeDialer(DialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return &stubProbeConn{}, nil
		})),
		WithWarpStatusChecker(checker),
		WithProbeConcurrency(30),
		WithProbeBatchTimeout(3*time.Second),
	)

	candidates := make([]Candidate, 35)
	for i := range candidates {
		candidates[i] = Candidate{Address: localProbeAddress443}
	}

	started := time.Now()
	results := prober.Probe(candidates)
	elapsed := time.Since(started)

	if elapsed > 3500*time.Millisecond {
		t.Fatalf("expected batch timeout near 3s, got %s", elapsed)
	}
	if len(results) >= len(candidates) {
		t.Fatalf("expected batch timeout to cut probing short, got %d results for %d candidates", len(results), len(candidates))
	}
	for _, result := range results {
		if !strings.Contains(result.Reason, "context deadline exceeded") {
			t.Fatalf("expected deadline reason, got %+v", result)
		}
	}
}

func TestBatchProbeSelectsBestFromPartialResults(t *testing.T) {
	t.Parallel()

	prober := partialProber{results: []ProbeResult{
		{Address: "fast:443", Available: true, WarpEnabled: true, Latency: 20 * time.Millisecond},
	}}

	result := BatchProbe(prober, []Candidate{
		{Address: "slow:443"},
		{Address: "fast:443"},
		{Address: "later:443"},
	})

	if !result.OK {
		t.Fatalf("expected partial results to still yield a best candidate, got %+v", result)
	}
	if result.Best.Address != "fast:443" {
		t.Fatalf("expected best partial result candidate, got %+v", result.Best)
	}
}

type partialProber struct {
	results []ProbeResult
}

func (p partialProber) Probe([]Candidate) []ProbeResult { return p.results }

type stubProbeConn struct {
	closed atomic.Bool
}

func (c *stubProbeConn) Read([]byte) (int, error)         { return 0, context.Canceled }
func (c *stubProbeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stubProbeConn) Close() error                     { c.closed.Store(true); return nil }
func (c *stubProbeConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (c *stubProbeConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (c *stubProbeConn) SetDeadline(time.Time) error      { return nil }
func (c *stubProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubProbeConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }
