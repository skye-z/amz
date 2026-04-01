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

const (
	localProbeAddress443      = testkit.LocalhostIPv4 + ":443"
	probePolicyFastEndpoint   = "fast:443"
	probePolicySelectedTarget = "selected:443"
)

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
		{Address: probePolicyFastEndpoint, Available: true, WarpEnabled: true, Latency: 20 * time.Millisecond},
	}}

	result := BatchProbe(prober, []Candidate{
		{Address: "slow:443"},
		{Address: probePolicyFastEndpoint},
		{Address: "later:443"},
	})

	if !result.OK {
		t.Fatalf("expected partial results to still yield a best candidate, got %+v", result)
	}
	if result.Best.Address != probePolicyFastEndpoint {
		t.Fatalf("expected best partial result candidate, got %+v", result.Best)
	}
}

func TestDiscoveryInternalHelpers(t *testing.T) {
	t.Parallel()

	if got := buildCacheCandidates(Cache{
		Selected:   Candidate{Address: probePolicySelectedTarget},
		Candidates: []Candidate{{Address: probePolicySelectedTarget}, {Address: "other:443"}},
	}); len(got) != 2 || got[0].Address != probePolicySelectedTarget {
		t.Fatalf("unexpected cache candidates: %+v", got)
	}

	plan := buildPreferredPlan(Registration{
		EndpointHost:  testkit.WarpHostPrimary,
		EndpointV4:    testkit.WarpIPv4Primary443,
		EndpointV6:    testkit.WarpIPv6Primary443,
		EndpointPorts: []uint16{443, 500},
	})
	if len(plan.Domains) == 0 || len(plan.Fixed) == 0 {
		t.Fatalf("expected preferred plan addresses, got %+v", plan)
	}

	if got := buildFixedCandidates([]string{"", " a:443 ", "a:443"}); len(got) != 2 {
		t.Fatalf("expected trimmed fixed candidates including duplicate raw entries, got %+v", got)
	}

	if got := dedupeCandidates([]Candidate{{Address: "a:443"}, {Address: "a:443"}, {Address: "b:443"}}); len(got) != 2 {
		t.Fatalf("unexpected deduped candidates: %+v", got)
	}
	if !containsCandidate([]Candidate{{Address: "a:443"}}, "a:443") {
		t.Fatal("expected containsCandidate match")
	}
	if got := warpProxyPortRank("missing-port"); got != 100 {
		t.Fatalf("expected unknown port rank 100, got %d", got)
	}
	if got := warpProxyPortRank("example.com:4500"); got != 3 {
		t.Fatalf("expected 4500 rank 3, got %d", got)
	}
	if got := candidateSourceRank("mystery"); got != 100 {
		t.Fatalf("expected unknown source rank 100, got %d", got)
	}

	primaryHost, _, err := net.SplitHostPort(testkit.WarpIPv4Primary443)
	if err != nil {
		t.Fatalf("unexpected primary endpoint parse error: %v", err)
	}
	fallbackHost, _, err := net.SplitHostPort(testkit.WarpIPv4Alt443)
	if err != nil {
		t.Fatalf("unexpected fallback endpoint parse error: %v", err)
	}
	fallbacks := observedWarpProxyFallbackHosts(primaryHost)
	if len(fallbacks) != 1 || fallbacks[0] != fallbackHost {
		t.Fatalf("unexpected fallback hosts: %+v", fallbacks)
	}
	if got := observedWarpProxyFallbackHosts(testkit.PublicDNSV4); got != nil {
		t.Fatalf("expected nil fallback hosts, got %+v", got)
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
