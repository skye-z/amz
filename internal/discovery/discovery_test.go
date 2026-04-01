package discovery_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/testkit"
)

const (
	localProbeEndpoint443  = testkit.LocalhostIPv4 + ":443"
	localProbeEndpoint500  = testkit.LocalhostIPv4 + ":500"
	localProbeEndpoint1701 = testkit.LocalhostIPv4 + ":1701"
	localProbeEndpoint4500 = testkit.LocalhostIPv4 + ":4500"
	testWarpIPv6Range126   = "2606:4700:103::/126"
	discoveryFastEndpoint  = "fast.example:443"
	discoverySlowEndpoint  = "slow.example:443"
	discoveryCachedFast    = "cached-fast.example:443"
	discoveryCachedSlow    = "cached-slow.example:443"
	discoveryScanNode      = "scan.example:443"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKind  string
		wantValue string
	}{
		{name: "fixed ip endpoint", input: testkit.WarpIPv4Primary443, wantKind: discovery.SourceFixed, wantValue: testkit.WarpIPv4Primary443},
		{name: "domain endpoint", input: testkit.WarpHostProxy443, wantKind: discovery.SourceDomain, wantValue: testkit.WarpHostProxy443},
		{name: "auto endpoint", input: "auto", wantKind: discovery.SourceAuto, wantValue: "auto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := discovery.ParseSource(tt.input)
			if err != nil {
				t.Fatalf("expected parse success, got %v", err)
			}
			if source.Kind != tt.wantKind {
				t.Fatalf("expected kind %q, got %q", tt.wantKind, source.Kind)
			}
			if source.Value != tt.wantValue {
				t.Fatalf("expected value %q, got %q", tt.wantValue, source.Value)
			}
		})
	}
}

func TestParseSourceRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "missing-port", "  "} {
		if _, err := discovery.ParseSource(input); err == nil {
			t.Fatalf("expected parse error for %q", input)
		}
	}
}

func TestBuildCandidatesCoversKinds(t *testing.T) {
	t.Parallel()

	if got := discovery.BuildCandidates(discovery.Source{Kind: discovery.SourceFixed, Value: testkit.WarpIPv4Primary443}); len(got) != 1 || got[0].Address != testkit.WarpIPv4Primary443 {
		t.Fatalf("unexpected fixed candidates: %+v", got)
	}
	if got := discovery.BuildCandidates(discovery.Source{Kind: discovery.SourceDomain, Value: testkit.WarpHostProxy443}); len(got) != 1 || got[0].Address != testkit.WarpHostProxy443 {
		t.Fatalf("unexpected domain candidates: %+v", got)
	}
	if got := discovery.BuildCandidates(discovery.Source{Kind: "unknown"}); got != nil {
		t.Fatalf("expected nil candidates for unknown kind, got %+v", got)
	}
}

func TestBuildCandidatesFromPlanDeduplicatesAddresses(t *testing.T) {
	plan := discovery.Plan{
		Source:  discovery.Source{Kind: discovery.SourceAuto, Value: "auto"},
		Range6:  []string{testWarpIPv6Range126},
		Fixed:   []string{testkit.WarpIPv6Primary443},
		Domains: []string{testkit.WarpHostProxy443},
	}

	candidates := discovery.BuildCandidatesFromPlan(plan, 443, 4)
	count := 0
	for _, candidate := range candidates {
		if candidate.Address == testkit.WarpIPv6Primary443 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduplicated candidate once, got %d in %+v", count, candidates)
	}
}

func TestPickBestCandidatePrefersPreferredWarpProxyPort(t *testing.T) {
	candidates := []discovery.Candidate{
		{Address: testkit.WarpIPv4Alt1701, Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 1 * time.Millisecond},
		{Address: testkit.WarpIPv4Alt500, Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 2 * time.Millisecond},
		{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 200 * time.Millisecond},
	}

	chosen, ok := discovery.PickBestCandidate(candidates)
	if !ok {
		t.Fatal("expected candidate selection")
	}
	if chosen.Address != testkit.WarpIPv4Alt443 {
		t.Fatalf("expected preferred port 443 candidate, got %q", chosen.Address)
	}
}

func TestBatchProbe(t *testing.T) {
	prober := discovery.NewStaticProber(map[string]discovery.ProbeResult{
		"a:443": {Address: "a:443", Available: true, WarpEnabled: true, Latency: 30 * time.Millisecond},
		"b:443": {Address: "b:443", Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
	})

	result := discovery.BatchProbe(prober, []discovery.Candidate{
		{Address: "a:443", Source: discovery.SourceAuto},
		{Address: "b:443", Source: discovery.SourceAuto},
	})

	if len(result.Candidates) != 2 {
		t.Fatalf("expected 2 updated candidates, got %d", len(result.Candidates))
	}
	if len(result.Ranked) != 2 {
		t.Fatalf("expected 2 ranked candidates, got %d", len(result.Ranked))
	}
	if !result.OK {
		t.Fatal("expected best candidate selection success")
	}
	if result.Best.Address != "b:443" {
		t.Fatalf("expected best candidate b:443, got %q", result.Best.Address)
	}
}

func TestAvailableCandidatesPreservesRankedAvailableOrder(t *testing.T) {
	ranked := []discovery.Candidate{
		{Address: discoveryFastEndpoint, Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
		{Address: "down.example:443", Available: false, WarpEnabled: false, Reason: "timeout"},
		{Address: discoverySlowEndpoint, Available: true, WarpEnabled: true, Latency: 20 * time.Millisecond},
	}

	available := discovery.AvailableCandidates(ranked)
	if len(available) != 2 {
		t.Fatalf("expected 2 available candidates, got %+v", available)
	}
	if available[0].Address != discoveryFastEndpoint || available[1].Address != discoverySlowEndpoint {
		t.Fatalf("expected available candidates to preserve ranked order, got %+v", available)
	}
}

func TestBuildVerificationCandidatesAddsObservedWarpProxyEndpoint(t *testing.T) {
	preferred, _ := discovery.BuildVerificationCandidates(discovery.Input{
		Registration: discovery.Registration{
			EndpointV4:    testkit.WarpIPv4Primary443,
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{},
	}, 443, 4)

	addresses := make([]string, 0, len(preferred))
	for _, candidate := range preferred {
		addresses = append(addresses, candidate.Address)
	}
	if !containsCandidateAddress(addresses, testkit.WarpIPv4Alt443) {
		t.Fatalf("expected observed proxy endpoint fallback %s, got %+v", testkit.WarpIPv4Alt443, addresses)
	}
}

func TestBuildVerificationCandidatesPrefersCacheReuse(t *testing.T) {
	preferred, fallback := discovery.BuildVerificationCandidates(discovery.Input{
		Cache: discovery.Cache{
			Selected: discovery.Candidate{
				Address:     discoveryCachedFast,
				Source:      discovery.SourceFixed,
				Available:   true,
				WarpEnabled: true,
				Latency:     3 * time.Millisecond,
			},
			Candidates: []discovery.Candidate{
				{Address: discoveryCachedSlow, Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 30 * time.Millisecond},
				{Address: discoveryCachedFast, Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 3 * time.Millisecond},
			},
		},
		Registration: discovery.Registration{
			EndpointV4:    testkit.WarpIPv4Primary443,
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{
			Fixed: []string{discoveryScanNode},
		},
	}, 443, 4)

	if len(preferred) == 0 || preferred[0].Address != discoveryCachedFast {
		t.Fatalf("expected cached selected candidate first, got %+v", preferred)
	}
	if len(fallback) == 0 || fallback[0].Address != discoveryScanNode {
		t.Fatalf("expected scan candidate in fallback list, got %+v", fallback)
	}
}

func TestBatchProbePlanUsesDefaults(t *testing.T) {
	t.Parallel()

	result := discovery.BatchProbePlan(discovery.Plan{
		Fixed: []string{testkit.WarpIPv4Primary443},
	}, discovery.NewStaticProber(map[string]discovery.ProbeResult{
		testkit.WarpIPv4Primary443: {
			Address:     testkit.WarpIPv4Primary443,
			Available:   true,
			WarpEnabled: true,
			Latency:     time.Millisecond,
		},
	}), 0, 0)

	if !result.OK || result.Best.Address != testkit.WarpIPv4Primary443 {
		t.Fatalf("expected batch probe plan success, got %+v", result)
	}
}

func TestSelectFallsBackToScannedCandidate(t *testing.T) {
	result := discovery.Select(discovery.Input{
		Registration: discovery.Registration{
			EndpointV4:    testkit.WarpIPv4Primary443,
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{
			Fixed: []string{discoverySlowEndpoint, discoveryFastEndpoint},
		},
	}, discovery.NewStaticProber(map[string]discovery.ProbeResult{
		testkit.WarpIPv4Primary443: {Address: testkit.WarpIPv4Primary443, Available: false, WarpEnabled: false, Reason: "dial_failed: timeout"},
		testkit.WarpIPv4Alt443:     {Address: testkit.WarpIPv4Alt443, Available: false, WarpEnabled: false, Reason: "dial_failed: timeout"},
		discoverySlowEndpoint:      {Address: discoverySlowEndpoint, Available: true, WarpEnabled: true, Latency: 40 * time.Millisecond},
		discoveryFastEndpoint:      {Address: discoveryFastEndpoint, Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
	}), 443, 4)

	if !result.OK {
		t.Fatalf("expected fallback selection success, got %+v", result)
	}
	if result.Best.Address != discoveryFastEndpoint {
		t.Fatalf("expected best scanned candidate %s, got %+v", discoveryFastEndpoint, result.Best)
	}
}

func TestRememberStoresBestAndRankedCandidates(t *testing.T) {
	cache := discovery.Remember(discovery.Cache{}, discovery.BatchResult{
		Ranked: []discovery.Candidate{
			{Address: discoveryFastEndpoint, Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
			{Address: discoverySlowEndpoint, Available: true, WarpEnabled: true, Latency: 20 * time.Millisecond},
		},
		Best: discovery.Candidate{Address: discoveryFastEndpoint, Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
		OK:   true,
	})

	if cache.Selected.Address != discoveryFastEndpoint {
		t.Fatalf("expected cached selected candidate, got %+v", cache.Selected)
	}
	if len(cache.Candidates) != 2 || cache.Candidates[0].Address != discoveryFastEndpoint {
		t.Fatalf("expected ranked candidates cached, got %+v", cache.Candidates)
	}
}

func TestRealProberSelectsNetworkByPort(t *testing.T) {
	var seen []string
	prober := discovery.NewRealProber(50*time.Millisecond, discovery.WithProbeDialer(discovery.DialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		seen = append(seen, network+" "+address)
		return nil, context.DeadlineExceeded
	})))

	_ = prober.Probe([]discovery.Candidate{
		{Address: localProbeEndpoint443},
		{Address: localProbeEndpoint500},
		{Address: localProbeEndpoint1701},
		{Address: localProbeEndpoint4500},
	})

	joined := strings.Join(seen, " | ")
	if !strings.Contains(joined, "tcp "+localProbeEndpoint443) {
		t.Fatalf("expected tcp probe for 443, got %q", joined)
	}
	if !strings.Contains(joined, "udp "+localProbeEndpoint500) {
		t.Fatalf("expected udp probe for 500, got %q", joined)
	}
	if !strings.Contains(joined, "udp "+localProbeEndpoint1701) {
		t.Fatalf("expected udp probe for 1701, got %q", joined)
	}
	if !strings.Contains(joined, "udp "+localProbeEndpoint4500) {
		t.Fatalf("expected udp probe for 4500, got %q", joined)
	}
}

func containsCandidateAddress(addresses []string, target string) bool {
	for _, address := range addresses {
		if address == target {
			return true
		}
	}
	return false
}
