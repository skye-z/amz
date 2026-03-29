package amz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
)

func TestTUNCandidateCheckerRequiresConnectIPReady(t *testing.T) {
	t.Parallel()

	state := storage.State{
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
		Interface: storage.InterfaceAddresses{
			V4: "172.16.0.2",
			V6: "2606:4700:110:8d36::2",
		},
	}
	mr := &managedRuntime{
		opts: Options{
			TUN: TUNOptions{Enabled: true},
		},
	}

	originalValidator := validateTUNCandidateForSelection
	defer func() { validateTUNCandidateForSelection = originalValidator }()

	called := false
	validateTUNCandidateForSelection = func(context.Context, Options, storage.State, discovery.Candidate) error {
		called = true
		return errors.New("connect-ip rejected")
	}

	checker := mr.newCandidateChecker(state)
	ok, err := checker.CheckWarp(context.Background(), discovery.Candidate{Address: "162.159.198.2:4500", Source: discovery.SourceFixed})
	if err == nil {
		t.Fatal("expected connect-ip validation error")
	}
	if ok {
		t.Fatal("expected candidate checker to reject candidate when connect-ip fails")
	}
	if !called {
		t.Fatal("expected tun candidate validator to be called")
	}
}

func TestTUNCandidateCheckerTimesOutWhenValidatorHangs(t *testing.T) {
	t.Parallel()

	state := storage.State{}
	mr := &managedRuntime{
		opts: Options{
			TUN: TUNOptions{Enabled: true},
		},
	}

	originalValidator := validateTUNCandidateForSelection
	defer func() { validateTUNCandidateForSelection = originalValidator }()

	validateTUNCandidateForSelection = func(ctx context.Context, opts Options, state storage.State, candidate discovery.Candidate) error {
		<-ctx.Done()
		select {}
	}

	checker := mr.newCandidateChecker(state)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	ok, err := checker.CheckWarp(ctx, discovery.Candidate{Address: "162.159.198.2:443", Source: discovery.SourceFixed})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if ok {
		t.Fatal("expected candidate checker to reject hanging validator")
	}
	if time.Since(started) > 300*time.Millisecond {
		t.Fatalf("expected checker to time out quickly, got %s", time.Since(started))
	}
}

func TestSelectEndpointUsesTUNTimingProfile(t *testing.T) {
	t.Parallel()

	state := storage.State{
		NodeCache: []storage.Node{{
			Host:       "engage.cloudflareclient.com:2408",
			EndpointV4: "162.159.198.1:443",
			EndpointV6: "[2606:4700:103::1]:443",
			Ports:      []uint16{443, 500, 1701, 4500, 4443, 8443, 8095},
		}},
	}
	logger := &capturingLogger{}
	mr := &managedRuntime{
		opts: Options{
			TUN:    TUNOptions{Enabled: true},
			Logger: logger,
		},
	}

	originalProbeProfile := tunProbeProfile
	originalValidate := validateTUNCandidateForSelection
	defer func() {
		tunProbeProfile = originalProbeProfile
		validateTUNCandidateForSelection = originalValidate
	}()

	tunProbeProfile = probeProfile{
		name:                "tun",
		perCandidateTimeout: 7 * time.Second,
		batchTimeout:        10 * time.Second,
		concurrency:         4,
	}
	validateTUNCandidateForSelection = func(ctx context.Context, opts Options, state storage.State, candidate discovery.Candidate) error {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(10 * time.Millisecond):
			return nil
		}
	}

	selection, _, err := mr.selectEndpoint(context.Background(), state)
	if err != nil {
		t.Fatalf("expected tun select success, got %v", err)
	}
	if selection.Primary.Address == "" {
		t.Fatal("expected selected candidate")
	}
	if len(selection.Candidates) == 0 {
		t.Fatal("expected ordered candidate list")
	}
	if selection.Candidates[0].Address != selection.Primary.Address {
		t.Fatalf("expected primary candidate to lead ordered list, got primary=%q list=%+v", selection.Primary.Address, selection.Candidates)
	}

	output := logger.String()
	for _, want := range []string{
		"probe_profile=\"tun\"",
		"per_candidate_timeout=\"7s\"",
		"batch_timeout=\"10s\"",
		"concurrency=4",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestPrioritizeTUNCandidatesPrefers198Dot2Endpoints(t *testing.T) {
	t.Parallel()

	candidates := []discovery.Candidate{
		{Address: "162.159.192.1:443", Source: discovery.SourceAuto},
		{Address: "engage.cloudflareclient.com:443", Source: discovery.SourceFixed},
		{Address: "162.159.198.1:443", Source: discovery.SourceFixed},
		{Address: "162.159.198.2:443", Source: discovery.SourceFixed},
		{Address: "162.159.198.2:500", Source: discovery.SourceFixed},
		{Address: "162.159.198.2:1701", Source: discovery.SourceFixed},
		{Address: "162.159.198.2:4500", Source: discovery.SourceFixed},
	}

	got := prioritizeTUNCandidates(candidates)
	wantPrefix := []string{
		"162.159.198.2:4500",
		"162.159.198.2:500",
		"162.159.198.2:1701",
		"162.159.198.2:443",
	}
	for i, want := range wantPrefix {
		if got[i].Address != want {
			t.Fatalf("expected candidate %d to be %q, got %+v", i, want, got)
		}
	}
}
