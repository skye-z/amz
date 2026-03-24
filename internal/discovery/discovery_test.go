package discovery_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/discovery"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKind  string
		wantValue string
	}{
		{name: "fixed ip endpoint", input: "162.159.198.1:443", wantKind: discovery.SourceFixed, wantValue: "162.159.198.1:443"},
		{name: "domain endpoint", input: "engage.cloudflareclient.com:443", wantKind: discovery.SourceDomain, wantValue: "engage.cloudflareclient.com:443"},
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

func TestBuildCandidatesFromPlanDeduplicatesAddresses(t *testing.T) {
	plan := discovery.Plan{
		Source:  discovery.Source{Kind: discovery.SourceAuto, Value: "auto"},
		Range6:  []string{"2606:4700:103::/126"},
		Fixed:   []string{"[2606:4700:103::1]:443"},
		Domains: []string{"engage.cloudflareclient.com:443"},
	}

	candidates := discovery.BuildCandidatesFromPlan(plan, 443, 4)
	count := 0
	for _, candidate := range candidates {
		if candidate.Address == "[2606:4700:103::1]:443" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduplicated candidate once, got %d in %+v", count, candidates)
	}
}

func TestPickBestCandidatePrefersPreferredWarpProxyPort(t *testing.T) {
	candidates := []discovery.Candidate{
		{Address: "162.159.198.2:1701", Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 1 * time.Millisecond},
		{Address: "162.159.198.2:500", Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 2 * time.Millisecond},
		{Address: "162.159.198.2:443", Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 200 * time.Millisecond},
	}

	chosen, ok := discovery.PickBestCandidate(candidates)
	if !ok {
		t.Fatal("expected candidate selection")
	}
	if chosen.Address != "162.159.198.2:443" {
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

func TestBuildVerificationCandidatesAddsObservedWarpProxyEndpoint(t *testing.T) {
	preferred, _ := discovery.BuildVerificationCandidates(discovery.Input{
		Registration: discovery.Registration{
			EndpointV4:    "162.159.198.1:443",
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{},
	}, 443, 4)

	addresses := make([]string, 0, len(preferred))
	for _, candidate := range preferred {
		addresses = append(addresses, candidate.Address)
	}
	if !containsCandidateAddress(addresses, "162.159.198.2:443") {
		t.Fatalf("expected observed proxy endpoint fallback 162.159.198.2:443, got %+v", addresses)
	}
}

func TestBuildVerificationCandidatesPrefersCacheReuse(t *testing.T) {
	preferred, fallback := discovery.BuildVerificationCandidates(discovery.Input{
		Cache: discovery.Cache{
			Selected: discovery.Candidate{
				Address:     "cached-fast.example:443",
				Source:      discovery.SourceFixed,
				Available:   true,
				WarpEnabled: true,
				Latency:     3 * time.Millisecond,
			},
			Candidates: []discovery.Candidate{
				{Address: "cached-slow.example:443", Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 30 * time.Millisecond},
				{Address: "cached-fast.example:443", Source: discovery.SourceFixed, Available: true, WarpEnabled: true, Latency: 3 * time.Millisecond},
			},
		},
		Registration: discovery.Registration{
			EndpointV4:    "162.159.198.1:443",
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{
			Fixed: []string{"scan.example:443"},
		},
	}, 443, 4)

	if len(preferred) == 0 || preferred[0].Address != "cached-fast.example:443" {
		t.Fatalf("expected cached selected candidate first, got %+v", preferred)
	}
	if len(fallback) == 0 || fallback[0].Address != "scan.example:443" {
		t.Fatalf("expected scan candidate in fallback list, got %+v", fallback)
	}
}

func TestSelectFallsBackToScannedCandidate(t *testing.T) {
	result := discovery.Select(discovery.Input{
		Registration: discovery.Registration{
			EndpointV4:    "162.159.198.1:443",
			EndpointPorts: []uint16{443},
		},
		Scan: discovery.Scan{
			Fixed: []string{"slow.example:443", "fast.example:443"},
		},
	}, discovery.NewStaticProber(map[string]discovery.ProbeResult{
		"162.159.198.1:443": {Address: "162.159.198.1:443", Available: false, WarpEnabled: false, Reason: "dial_failed: timeout"},
		"162.159.198.2:443": {Address: "162.159.198.2:443", Available: false, WarpEnabled: false, Reason: "dial_failed: timeout"},
		"slow.example:443":  {Address: "slow.example:443", Available: true, WarpEnabled: true, Latency: 40 * time.Millisecond},
		"fast.example:443":  {Address: "fast.example:443", Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
	}), 443, 4)

	if !result.OK {
		t.Fatalf("expected fallback selection success, got %+v", result)
	}
	if result.Best.Address != "fast.example:443" {
		t.Fatalf("expected best scanned candidate fast.example:443, got %+v", result.Best)
	}
}

func TestRememberStoresBestAndRankedCandidates(t *testing.T) {
	cache := discovery.Remember(discovery.Cache{}, discovery.BatchResult{
		Ranked: []discovery.Candidate{
			{Address: "fast.example:443", Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
			{Address: "slow.example:443", Available: true, WarpEnabled: true, Latency: 20 * time.Millisecond},
		},
		Best: discovery.Candidate{Address: "fast.example:443", Available: true, WarpEnabled: true, Latency: 5 * time.Millisecond},
		OK:   true,
	})

	if cache.Selected.Address != "fast.example:443" {
		t.Fatalf("expected cached selected candidate, got %+v", cache.Selected)
	}
	if len(cache.Candidates) != 2 || cache.Candidates[0].Address != "fast.example:443" {
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
		{Address: "127.0.0.1:443"},
		{Address: "127.0.0.1:500"},
		{Address: "127.0.0.1:1701"},
		{Address: "127.0.0.1:4500"},
	})

	joined := strings.Join(seen, " | ")
	if !strings.Contains(joined, "tcp 127.0.0.1:443") {
		t.Fatalf("expected tcp probe for 443, got %q", joined)
	}
	if !strings.Contains(joined, "udp 127.0.0.1:500") {
		t.Fatalf("expected udp probe for 500, got %q", joined)
	}
	if !strings.Contains(joined, "udp 127.0.0.1:1701") {
		t.Fatalf("expected udp probe for 1701, got %q", joined)
	}
	if !strings.Contains(joined, "udp 127.0.0.1:4500") {
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
