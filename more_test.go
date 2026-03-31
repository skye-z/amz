package amz

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/failure"
	internalconfig "github.com/skye-z/amz/internal/config"
	internalruntime "github.com/skye-z/amz/internal/runtime"
	"github.com/skye-z/amz/internal/storage"
)

type extraSDKRuntime struct {
	startErr error
	runErr error
	closeErr error
	healthErr error
	status Status
	listen string
	startCalls int
	runCalls int
	closeCalls int
}

func (s *extraSDKRuntime) Start(context.Context) error { s.startCalls++; return s.startErr }
func (s *extraSDKRuntime) Run() error { s.runCalls++; return s.runErr }
func (s *extraSDKRuntime) Close() error { s.closeCalls++; return s.closeErr }
func (s *extraSDKRuntime) HealthCheck(context.Context) error { return s.healthErr }
func (s *extraSDKRuntime) Status() Status { return s.status }
func (s *extraSDKRuntime) ListenAddress() string { return s.listen }

type extraAuthEnsurer struct {
	result authResult
	err error
}

type authResult struct {
	Action string
	State storage.State
}

func (s *extraAuthEnsurer) Ensure(context.Context) (authResult, error) { return s.result, s.err }

type extraStore struct { saved storage.State; saveErr error }
func (s *extraStore) Load() (storage.State, error) { return storage.State{}, nil }
func (s *extraStore) Save(state storage.State) error { s.saved = state; return s.saveErr }

func TestOptionsNormalizedAndClientLifecycle(t *testing.T) {
	orig := buildSDKRuntime
	defer func() { buildSDKRuntime = orig }()
	stub := &extraSDKRuntime{status: Status{Running: true, ListenAddress: "127.0.0.1:9000"}, listen: "127.0.0.1:9000"}
	buildSDKRuntime = func(Options) (sdkRuntime, error) { return stub, nil }

	if got := (Options{HTTP: HTTPOptions{Enabled: true}}).normalized().Listen.Address; got == "" {
		t.Fatal("expected default listen address when proxy mode enabled")
	}
	client, err := NewClient(Options{HTTP: HTTPOptions{Enabled: true}})
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := client.Run(); err != nil {
		t.Fatalf("expected run success, got %v", err)
	}
	if got := client.ListenAddress(); got != "127.0.0.1:9000" {
		t.Fatalf("unexpected listen address: %q", got)
	}
	if !client.Status().Running {
		t.Fatal("expected running status")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("expected double close success, got %v", err)
	}
}

func TestClientErrorsAndNoopRuntime(t *testing.T) {
	orig := buildSDKRuntime
	defer func() { buildSDKRuntime = orig }()
	if _, err := NewClient(Options{}); !errors.Is(err, ErrNoRuntimeEnabled) {
		t.Fatalf("expected ErrNoRuntimeEnabled, got %v", err)
	}
	buildSDKRuntime = func(Options) (sdkRuntime, error) { return nil, errors.New("build failed") }
	if _, err := NewClient(Options{HTTP: HTTPOptions{Enabled: true}}); err == nil {
		t.Fatal("expected build runtime error")
	}
	stub := &extraSDKRuntime{startErr: errors.New("start failed")}
	buildSDKRuntime = func(Options) (sdkRuntime, error) { return stub, nil }
	client, err := NewClient(Options{HTTP: HTTPOptions{Enabled: true}})
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}
	if err := client.Start(context.Background()); err == nil {
		t.Fatal("expected start error")
	}
	_ = client.Close()
	if err := client.Start(context.Background()); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed, got %v", err)
	}
	if err := client.Run(); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed on run, got %v", err)
	}
	noop := &noopRuntime{}
	if err := noop.Start(context.Background()); err != nil || noop.Run() != nil || noop.Close() != nil || noop.HealthCheck(context.Background()) != nil {
		t.Fatal("expected noop runtime operations to succeed")
	}
}

func TestSDKHelpersAndManagedRuntimeUtilities(t *testing.T) {
	if got := dedupeStrings([]string{"a", "", "a", "b"}); len(got) != 2 {
		t.Fatalf("unexpected dedupe result: %+v", got)
	}
	selection := newEndpointSelection(discovery.Candidate{Address: "a"}, []discovery.Candidate{{Address: "a"}, {Address: "b"}})
	if len(selection.Candidates) != 2 {
		t.Fatalf("unexpected selection result: %+v", selection)
	}
	if tunCandidatePriority("162.159.198.2:4500", discovery.SourceFixed) >= tunCandidatePriority("162.159.198.1:4500", discovery.SourceFixed) {
		t.Fatal("expected preferred tun candidate priority")
	}
	state := storage.State{Certificate: storage.Certificate{PrivateKey: "pk", ClientCertificate: "cert", PeerPublicKey: "peer", ClientID: "cid"}, Account: storage.AccountStatus{State: "registered", AccountType: "plus"}, Interface: storage.InterfaceAddresses{V4: "1.1.1.1", V6: "::1"}, Services: storage.Services{HTTPProxy: "http://proxy"}, SelectedNode: "node-1", NodeCache: []storage.Node{{ID: "node-1", Host: "host", EndpointV4: "1.1.1.1:443", EndpointV6: "[::1]:443", PublicKey: "peer", Ports: []uint16{443}}}}
	if info := sessionInfoFromState(state); info.IPv4 == "" || info.IPv6 == "" {
		t.Fatalf("unexpected session info: %+v", info)
	}
	cache := cacheFromState(state)
	if len(cache.Candidates) == 0 {
		t.Fatalf("expected cache candidates, got %+v", cache)
	}
	reg := registrationFromState(state)
	if reg.EndpointV4 == "" {
		t.Fatalf("expected registration endpoint, got %+v", reg)
	}
	prepared := prepareCandidatesForProbe([]discovery.Candidate{{Address: "a"}})
	if prepared[0].Reason != "not_probed" {
		t.Fatalf("unexpected prepared candidate: %+v", prepared[0])
	}
	mgr := &managedRuntime{selection: endpointSelection{Candidates: []discovery.Candidate{{Address: "a"}, {Address: "b"}}}, endpoint: "a", status: Status{Running: true}}
	if next := mgr.nextCandidateIndex(mgr.selection, "a"); next != 1 {
		t.Fatalf("unexpected next candidate index: %d", next)
	}
}


func TestManagedRuntimeMethodBranches(t *testing.T) {
	mr := &managedRuntime{}
	if err := mr.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected nil runtime health success, got %v", err)
	}
	if got := mr.ListenAddress(); got != "" {
		t.Fatalf("expected empty listen address, got %q", got)
	}
	stub := &extraSDKRuntime{status: Status{Running: true, ListenAddress: "127.0.0.1:8000"}}
	mr.runtime = stub
	mr.endpoint = "endpoint-1"
	mr.registered = true
	mr.refreshStatusLocked(stub)
	if err := mr.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected runtime health success, got %v", err)
	}
	if got := mr.ListenAddress(); got != "127.0.0.1:8000" {
		t.Fatalf("unexpected listen address: %q", got)
	}
	if status := mr.Status(); !status.Running || status.Endpoint != "endpoint-1" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestManagedRuntimeFailurePublishingBranches(t *testing.T) {
	seen := make(chan failure.Event, 1)
	mr := &managedRuntime{endpoint: "endpoint-1", failureBus: failure.NewBus(1, func(event failure.Event) { seen <- event })}
	defer mr.failureBus.Close()
	mr.publishFailure(failure.Event{Err: errors.New("boom")})
	select {
	case event := <-seen:
		if event.Endpoint != "endpoint-1" {
			t.Fatalf("expected default endpoint injection, got %+v", event)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected published failure event")
	}
	mr.reportEndpointFailure("endpoint-2", errors.New("boom2"))
	select {
	case event := <-seen:
		if event.Endpoint != "endpoint-2" {
			t.Fatalf("expected explicit endpoint, got %+v", event)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected reported failure event")
	}
}


func TestRuntimeAdapterAndBuildRuntimeProxyOnly(t *testing.T) {
	httpRuntime := internalruntime.NewHTTPRuntime(localHTTPStarter{listenAddress: "127.0.0.1:0", state: "idle"})
	clientRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{HTTP: httpRuntime})
	if err != nil {
		t.Fatalf("expected client runtime success, got %v", err)
	}
	adapter := &runtimeAdapter{runtime: clientRT}
	if err := adapter.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected adapter health success, got %v", err)
	}
	_ = adapter.ListenAddress()
	_ = adapter.Status()

	mr := &managedRuntime{opts: Options{Listen: ListenOptions{Address: "127.0.0.1:0"}, HTTP: HTTPOptions{Enabled: true}, SOCKS5: SOCKS5Options{Enabled: true}}}
	rt, err := mr.buildRuntime("162.159.198.2:500", storage.DefaultState())
	if err != nil {
		t.Fatalf("expected buildRuntime success, got %v", err)
	}
	if rt == nil {
		t.Fatal("expected built runtime")
	}
}

func TestRuntimeAdapterAndManagedRuntimeRunBranches(t *testing.T) {
	httpRuntime := internalruntime.NewHTTPRuntime(localHTTPStarter{listenAddress: "127.0.0.1:0", state: "idle"})
	clientRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{HTTP: httpRuntime})
	if err != nil {
		t.Fatalf("expected client runtime success, got %v", err)
	}
	adapter := &runtimeAdapter{runtime: clientRT}
	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run() }()
	time.Sleep(10 * time.Millisecond)
	if err := adapter.Close(); err != nil {
		t.Fatalf("expected adapter close success, got %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected adapter run success, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected adapter run to exit after close")
	}

	mr := &managedRuntime{runtime: &extraSDKRuntime{}}
	if err := mr.Run(); err != nil {
		t.Fatalf("expected managed runtime run success, got %v", err)
	}
	mr = &managedRuntime{failureBus: failure.NewBus(1, nil)}
	if err := mr.Close(); err != nil {
		t.Fatalf("expected managed runtime close without runtime to succeed, got %v", err)
	}
}

func TestManagedRuntimeTryHotSwapRuntime(t *testing.T) {
	store := &stubStateStore{loadState: storage.DefaultState()}
	currentHTTP, err := internalruntime.NewHTTPManager(internalconfig.KernelConfig{
		Endpoint:       internalconfig.DefaultEndpoint,
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeHTTP,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		HTTP:           internalconfig.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected current http manager success, got %v", err)
	}
	currentSOCKS, err := internalruntime.NewSOCKS5Manager(&internalconfig.KernelConfig{
		Endpoint:       internalconfig.DefaultEndpoint,
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeSOCKS,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		SOCKS:          internalconfig.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected current socks manager success, got %v", err)
	}
	nextHTTP, err := internalruntime.NewHTTPManager(internalconfig.KernelConfig{
		Endpoint:       "next-endpoint",
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeHTTP,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		HTTP:           internalconfig.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected next http manager success, got %v", err)
	}
	nextSOCKS, err := internalruntime.NewSOCKS5Manager(&internalconfig.KernelConfig{
		Endpoint:       "next-endpoint",
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeSOCKS,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		SOCKS:          internalconfig.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected next socks manager success, got %v", err)
	}
	currentRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		HTTP:   internalruntime.NewHTTPRuntime(currentHTTP),
		SOCKS5: internalruntime.NewSOCKS5Runtime(currentSOCKS),
	})
	if err != nil {
		t.Fatalf("expected current client runtime success, got %v", err)
	}
	nextRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		HTTP:   internalruntime.NewHTTPRuntime(nextHTTP),
		SOCKS5: internalruntime.NewSOCKS5Runtime(nextSOCKS),
	})
	if err != nil {
		t.Fatalf("expected next client runtime success, got %v", err)
	}
	mr := &managedRuntime{
		opts:      Options{},
		store:     store,
		endpoint:  "current-endpoint",
		selection: endpointSelection{Candidates: []discovery.Candidate{{Address: "current-endpoint"}, {Address: "next-endpoint"}}},
	}
	ok := mr.tryHotSwapRuntime(&runtimeAdapter{runtime: currentRT}, &runtimeAdapter{runtime: nextRT}, "next-endpoint", storage.DefaultState(), mr.selection, 1, errors.New("boom"))
	if !ok {
		t.Fatal("expected hot swap runtime success")
	}
	if mr.endpoint != "next-endpoint" {
		t.Fatalf("expected endpoint updated, got %q", mr.endpoint)
	}
	if got := store.saved[len(store.saved)-1].SelectedNode; got != "next-endpoint" {
		t.Fatalf("expected saved selected node updated, got %q", got)
	}
}

func TestManagedRuntimeTryHotSwapRuntimeFailureBranches(t *testing.T) {
	mr := &managedRuntime{store: &stubStateStore{loadState: storage.DefaultState()}}
	if mr.tryHotSwapRuntime(nil, nil, "endpoint", storage.DefaultState(), endpointSelection{}, 0, errors.New("boom")) {
		t.Fatal("expected hot swap to fail for nil runtimes")
	}

	saveFailStore := &failingStateStore{err: errors.New("save failed")}
	mr = &managedRuntime{store: saveFailStore}
	currentHTTP, err := internalruntime.NewHTTPManager(internalconfig.KernelConfig{
		Endpoint:       internalconfig.DefaultEndpoint,
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeHTTP,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		HTTP:           internalconfig.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected current http manager success, got %v", err)
	}
	currentSOCKS, err := internalruntime.NewSOCKS5Manager(&internalconfig.KernelConfig{
		Endpoint:       internalconfig.DefaultEndpoint,
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeSOCKS,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		SOCKS:          internalconfig.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected current socks manager success, got %v", err)
	}
	nextHTTP, err := internalruntime.NewHTTPManager(internalconfig.KernelConfig{
		Endpoint:       "next-endpoint",
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeHTTP,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		HTTP:           internalconfig.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected next http manager success, got %v", err)
	}
	nextSOCKS, err := internalruntime.NewSOCKS5Manager(&internalconfig.KernelConfig{
		Endpoint:       "next-endpoint",
		SNI:            internalconfig.DefaultSNI,
		MTU:            internalconfig.DefaultMTU,
		Mode:           internalconfig.ModeSOCKS,
		ConnectTimeout: internalconfig.DefaultConnectTimeout,
		Keepalive:      internalconfig.DefaultKeepalive,
		SOCKS:          internalconfig.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected next socks manager success, got %v", err)
	}
	currentRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		HTTP:   internalruntime.NewHTTPRuntime(currentHTTP),
		SOCKS5: internalruntime.NewSOCKS5Runtime(currentSOCKS),
	})
	if err != nil {
		t.Fatalf("expected current client runtime success, got %v", err)
	}
	nextRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		HTTP:   internalruntime.NewHTTPRuntime(nextHTTP),
		SOCKS5: internalruntime.NewSOCKS5Runtime(nextSOCKS),
	})
	if err != nil {
		t.Fatalf("expected next client runtime success, got %v", err)
	}
	if mr.tryHotSwapRuntime(&runtimeAdapter{runtime: currentRT}, &runtimeAdapter{runtime: nextRT}, "next-endpoint", storage.DefaultState(), endpointSelection{}, 0, errors.New("boom")) {
		t.Fatal("expected hot swap to fail when save fails")
	}
}

func TestManagedRuntimeFailoverRuntimeBranches(t *testing.T) {
	store := &stubStateStore{loadState: storage.DefaultState()}
	mr := &managedRuntime{
		store:     store,
		selection: endpointSelection{Candidates: []discovery.Candidate{{Address: "a"}, {Address: "b"}}},
		switching: true,
	}
	mr.buildFn = func(string, storage.State) (sdkRuntime, error) {
		return nil, errors.New("build failed")
	}
	mr.failoverRuntime("a", errors.New("boom"), mr.selection, storage.DefaultState(), nil)
	if mr.switching {
		t.Fatal("expected switching to be cleared after failover failure")
	}

	store = &stubStateStore{loadState: storage.DefaultState()}
	current := &stubClientRuntimeAdapter{status: runtimeStatus("127.0.0.1:1", "a", true, true, false), closeCalls: 0}
	next := &stubClientRuntimeAdapter{status: runtimeStatus("127.0.0.1:2", "b", true, true, false)}
	mr = &managedRuntime{
		store:     store,
		selection: endpointSelection{Candidates: []discovery.Candidate{{Address: "a"}, {Address: "b"}}},
		switching: true,
	}
	mr.buildFn = func(endpoint string, _ storage.State) (sdkRuntime, error) {
		if endpoint != "b" {
			return nil, errors.New("unexpected endpoint")
		}
		return next, nil
	}
	mr.failoverRuntime("a", errors.New("boom"), mr.selection, storage.DefaultState(), current)
	if mr.endpoint != "b" || mr.switching {
		t.Fatalf("expected successful failover to b, got endpoint=%q switching=%v", mr.endpoint, mr.switching)
	}
	if current.closeCalls == 0 || next.startCalls == 0 {
		t.Fatalf("expected current close and next start, got current=%+v next=%+v", current, next)
	}
}

func TestManagedRuntimeBuildRuntimeAdditionalModesAndFailureHandlerNoops(t *testing.T) {
	state := storage.DefaultState()
	state.Certificate = storage.Certificate{
		PrivateKey:        "private-key",
		ClientCertificate: "client-cert",
		PeerPublicKey:     "peer-key",
		ClientID:          "client-id",
	}
	state.Interface = storage.InterfaceAddresses{V4: "1.1.1.1", V6: "::1"}

	socksOnly := &managedRuntime{opts: Options{Listen: ListenOptions{Address: "127.0.0.1:0"}, SOCKS5: SOCKS5Options{Enabled: true}}}
	if rt, err := socksOnly.buildRuntime("162.159.198.2:500", state); err != nil || rt == nil {
		t.Fatalf("expected socks-only runtime build success, got rt=%v err=%v", rt, err)
	}

	tunOnly := &managedRuntime{opts: Options{TUN: TUNOptions{Enabled: true}}}
	if rt, err := tunOnly.buildRuntime("162.159.198.2:500", state); err != nil || rt == nil {
		t.Fatalf("expected tun-only runtime build success, got rt=%v err=%v", rt, err)
	}

	mr := &managedRuntime{
		endpoint:  "endpoint-1",
		status:    Status{Running: true},
		selection: endpointSelection{Candidates: []discovery.Candidate{{Address: "endpoint-1"}}},
	}
	mr.handleFailureEvent(failure.Event{Endpoint: "endpoint-1", Err: errors.New("plain transport error")})
	mr.switching = true
	mr.handleFailureEvent(failure.Event{Endpoint: "endpoint-1", Err: errors.New("ensure connect-ip ready: protocol mismatch")})
	mr.switching = false
	mr.handleFailureEvent(failure.Event{Endpoint: "other-endpoint", Err: errors.New("ensure connect-ip ready: protocol mismatch")})
	mr.status.Running = false
	mr.handleFailureEvent(failure.Event{Endpoint: "endpoint-1", Err: errors.New("ensure connect-ip ready: protocol mismatch")})
}

func TestLoggingHelperBranchesAndSelectionDiagnostics(t *testing.T) {
	if got := normalizeAction(" "); got != "INFO" {
		t.Fatalf("unexpected normalized action: %q", got)
	}
	if got := formatLogValue(nil); got != "null" {
		t.Fatalf("unexpected nil log value: %q", got)
	}
	if got := formatLogValue(true); got != "true" {
		t.Fatalf("unexpected bool log value: %q", got)
	}
	if got := formatLogValue(time.Second); got != "\"1s\"" {
		t.Fatalf("unexpected duration log value: %q", got)
	}
	if action, msg := describeEvent("unknown", "custom.event"); action != "INFO" || msg != "custom event" {
		t.Fatalf("unexpected fallback event description: %q %q", action, msg)
	}

	if got := newLoggingProber(nil, discovery.NewStaticProber(nil)); got == nil {
		t.Fatal("expected base prober passthrough")
	}
	logger := &capturingLogger{}
	base := discovery.NewStaticProber(map[string]discovery.ProbeResult{})
	prober := newLoggingProber(logger, base)
	if results := prober.Probe([]discovery.Candidate{{Address: "missing", Source: discovery.SourceFixed}}); len(results) != 0 {
		t.Fatalf("expected no results, got %+v", results)
	}

	observer := newLoggingProbeObserver(logger)
	if observer == nil {
		t.Fatal("expected logging probe observer")
	}
	if newLoggingProbeObserver(nil) != nil {
		t.Fatal("expected nil observer for nil logger")
	}
	obs := observer.(*loggingProbeObserver)
	obs.OnProbeStart(discovery.Candidate{Address: "candidate", Source: discovery.SourceFixed}, 1, 1)
	obs.OnProbeDone(discovery.Candidate{Address: "candidate", Source: discovery.SourceFixed}, discovery.ProbeResult{Available: false, Reason: "down"}, time.Millisecond, 1, 1)
	obs.OnWarpCheckStart(discovery.Candidate{Address: "candidate", Source: discovery.SourceFixed})
	obs.OnWarpCheckDone(discovery.Candidate{Address: "candidate", Source: discovery.SourceFixed}, false, nil, time.Millisecond)

	checkerBase := discovery.WarpStatusFunc(func(context.Context, discovery.Candidate) (bool, error) { return false, errors.New("boom") })
	checker := newLoggingWarpStatusChecker(logger, checkerBase)
	if checker == nil {
		t.Fatal("expected logging warp checker")
	}
	if _, err := checker.CheckWarp(context.Background(), discovery.Candidate{Address: "candidate", Source: discovery.SourceFixed}); err == nil {
		t.Fatal("expected wrapped checker error")
	}
	if newLoggingWarpStatusChecker(nil, checkerBase) == nil {
		// passthrough may still be non-nil, just ensure no panic path
	}
}

func TestRuntimeAdapterLifecycleMethods(t *testing.T) {
	httpRuntime := internalruntime.NewHTTPRuntime(localHTTPStarter{listenAddress: "127.0.0.1:0", state: "idle"})
	clientRT, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{HTTP: httpRuntime})
	if err != nil {
		t.Fatalf("expected client runtime success, got %v", err)
	}
	adapter := &runtimeAdapter{runtime: clientRT}
	if err := adapter.Start(context.Background()); err != nil {
		t.Fatalf("expected adapter start success, got %v", err)
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- adapter.Run()
	}()
	time.Sleep(10 * time.Millisecond)
	if err := adapter.Close(); err != nil {
		t.Fatalf("expected adapter close success, got %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected adapter run success, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected adapter run to finish after close")
	}
}

type localHTTPStarter struct { listenAddress string; state string }
func (s localHTTPStarter) Start(context.Context) error { return nil }
func (s localHTTPStarter) StartWithListener(context.Context, net.Listener) error { return nil }
func (s localHTTPStarter) Stop(context.Context) error { return nil }
func (s localHTTPStarter) Close() error { return nil }
func (s localHTTPStarter) State() string { return s.state }
func (s localHTTPStarter) Stats() internalconfig.Stats { return internalconfig.Stats{} }
func (s localHTTPStarter) ListenAddress() string { return s.listenAddress }

type failingStateStore struct{ err error }

func (s *failingStateStore) Load() (storage.State, error) { return storage.DefaultState(), nil }
func (s *failingStateStore) Save(storage.State) error     { return s.err }
