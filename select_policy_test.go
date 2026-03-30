package amz

import (
	"testing"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
)

func TestBuildDiscoveryInputDropsIPv6WhenUnavailable(t *testing.T) {
	t.Parallel()

	state := storage.State{
		NodeCache: []storage.Node{{
			Host:       testkit.WarpHostPrimary,
			EndpointV4: testkit.WarpIPv4Primary443,
			EndpointV6: testkit.WarpIPv6Primary443,
			Ports:      []uint16{443, 500},
		}},
	}

	input := buildDiscoveryInput(state, false)
	if input.Registration.EndpointV6 != "" {
		t.Fatalf("expected ipv6 registration endpoint to be removed, got %q", input.Registration.EndpointV6)
	}
	if len(input.Scan.Range6) != 0 {
		t.Fatalf("expected ipv6 ranges to be removed, got %+v", input.Scan.Range6)
	}
}

func TestFilterCandidatesByIPv6Support(t *testing.T) {
	t.Parallel()

	filtered := filterCandidatesByIPv6Support([]discovery.Candidate{
		{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv6Primary443, Source: discovery.SourceFixed},
		{Address: testkit.WarpHostProxy443, Source: discovery.SourceDomain},
	}, false)

	if len(filtered) != 2 {
		t.Fatalf("expected only ipv4/domain candidates to remain, got %+v", filtered)
	}
	for _, candidate := range filtered {
		if candidate.Address == testkit.WarpIPv6Primary443 {
			t.Fatalf("expected ipv6 literal candidate to be filtered, got %+v", filtered)
		}
	}
}
