package amz

import (
	"context"
	"errors"
	"fmt"
	"github.com/skye-z/amz/internal/auth"
	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/failure"
	internalruntime "github.com/skye-z/amz/internal/runtime"
	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewClientRejectsNoEnabledRuntime(t *testing.T) {
	t.Parallel()

	_, err := NewClient(Options{})
	if err == nil {
		t.Fatal("expected configuration error when no runtime is enabled")
	}
}

func TestNewClientAppliesDefaultListenAddressForProxyModes(t *testing.T) {
	t.Parallel()

	client, err := NewClient(Options{
		HTTP: HTTPOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}
	if client.opts.Listen.Address != testkit.LocalListenSDK {
		t.Fatalf("expected default listen address, got %q", client.opts.Listen.Address)
	}
}

func TestClientStartCloseAndStatus(t *testing.T) {
	t.Parallel()

	originalBuilder := buildSDKRuntime
	defer func() { buildSDKRuntime = originalBuilder }()

	runtime := &stubSDKRuntime{
		status: Status{
			Running:       true,
			ListenAddress: testkit.LocalListenSDK,
			Endpoint:      testkit.WarpIPv4Alt443,
			HTTPEnabled:   true,
			SOCKS5Enabled: true,
			Registered:    true,
		},
	}
	buildSDKRuntime = func(Options) (sdkRuntime, error) {
		return runtime, nil
	}

	client, err := NewClient(Options{
		HTTP:   HTTPOptions{Enabled: true},
		SOCKS5: SOCKS5Options{Enabled: true},
	})
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}

	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if runtime.startCalls != 1 {
		t.Fatalf("expected runtime start once, got %d", runtime.startCalls)
	}
	if client.ListenAddress() != testkit.LocalListenSDK {
		t.Fatalf("expected listen address from runtime, got %q", client.ListenAddress())
	}
	status := client.Status()
	if !status.Running || !status.Registered || status.Endpoint != testkit.WarpIPv4Alt443 {
		t.Fatalf("unexpected status: %+v", status)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if runtime.closeCalls != 1 {
		t.Fatalf("expected runtime close once, got %d", runtime.closeCalls)
	}
}

func TestManagedRuntimePersistsSelectedNodeAndStatus(t *testing.T) {
	t.Parallel()

	originalAuthFactory := newDefaultAuthService
	defer func() { newDefaultAuthService = originalAuthFactory }()

	store := &stubStateStore{loadState: storage.DefaultState()}
	authState := storage.State{
		Version:  storage.CurrentVersion,
		DeviceID: "device-123",
		Token:    "token-123",
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
	}
	mr := &managedRuntime{
		opts: Options{
			Listen: ListenOptions{Address: testkit.LocalListenSDK},
			HTTP:   HTTPOptions{Enabled: true},
			SOCKS5: SOCKS5Options{Enabled: true},
		},
		store: store,
		auth:  &stubAuthEnsurer{result: authState},
		status: Status{
			HTTPEnabled:   true,
			SOCKS5Enabled: true,
		},
	}
	mr.selectFn = func(context.Context, storage.State) (endpointSelection, []storage.Node, error) {
		candidate := discovery.Candidate{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true}
		return endpointSelection{Primary: candidate, Candidates: []discovery.Candidate{candidate}}, []storage.Node{
			{ID: "node-1", EndpointV4: testkit.WarpIPv4Alt443},
		}, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		return &stubClientRuntimeAdapter{status: runtimeStatus(testkit.LocalListenSDK, endpoint, true, true, false)}, nil
	}

	err := mr.Start(context.Background())
	if err != nil {
		t.Fatalf("expected managed runtime start success, got %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("expected one state save, got %d", len(store.saved))
	}
	if store.saved[0].SelectedNode != testkit.WarpIPv4Alt443 {
		t.Fatalf("expected selected node persisted, got %+v", store.saved[0])
	}
	status := mr.Status()
	if !status.Running || status.ListenAddress != testkit.LocalListenSDK || status.Endpoint != testkit.WarpIPv4Alt443 || !status.Registered {
		t.Fatalf("unexpected managed runtime status: %+v", status)
	}
}

func TestManagedRuntimeFailsOverToNextEndpointOnStartFailure(t *testing.T) {
	t.Parallel()

	store := &stubStateStore{loadState: storage.DefaultState()}
	authState := storage.State{
		Version: storage.CurrentVersion,
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
	}

	firstRuntime := &stubClientRuntimeAdapter{
		status:   runtimeStatus(testkit.LocalListenSDK, testkit.WarpIPv4Primary443, true, true, false),
		startErr: errors.New("dial failed"),
	}
	secondRuntime := &stubClientRuntimeAdapter{
		status: runtimeStatus(testkit.LocalListenSDK, testkit.WarpIPv4Alt443, true, true, false),
	}

	var built []string
	mr := &managedRuntime{
		opts: Options{
			Listen: ListenOptions{Address: testkit.LocalListenSDK},
			HTTP:   HTTPOptions{Enabled: true},
			SOCKS5: SOCKS5Options{Enabled: true},
		},
		store: store,
		auth:  &stubAuthEnsurer{result: authState},
		status: Status{
			HTTPEnabled:   true,
			SOCKS5Enabled: true,
		},
	}
	mr.selectFn = func(context.Context, storage.State) (endpointSelection, []storage.Node, error) {
		candidates := []discovery.Candidate{
			{Address: testkit.WarpIPv4Primary443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
			{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
		}
		return endpointSelection{Primary: candidates[0], Candidates: candidates}, []storage.Node{
			{ID: "node-1", EndpointV4: testkit.WarpIPv4Alt443},
		}, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		built = append(built, endpoint)
		switch endpoint {
		case testkit.WarpIPv4Primary443:
			return firstRuntime, nil
		case testkit.WarpIPv4Alt443:
			return secondRuntime, nil
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil, nil
		}
	}

	if err := mr.Start(context.Background()); err != nil {
		t.Fatalf("expected failover start success, got %v", err)
	}
	if got, want := strings.Join(built, ","), testkit.WarpIPv4Primary443+","+testkit.WarpIPv4Alt443; got != want {
		t.Fatalf("expected build order %q, got %q", want, got)
	}
	if firstRuntime.closeCalls != 1 {
		t.Fatalf("expected failed runtime to be closed once, got %d", firstRuntime.closeCalls)
	}
	if len(store.saved) != 1 || store.saved[0].SelectedNode != testkit.WarpIPv4Alt443 {
		t.Fatalf("expected only successful endpoint to be persisted, got %+v", store.saved)
	}
	status := mr.Status()
	if status.Endpoint != testkit.WarpIPv4Alt443 || !status.Running {
		t.Fatalf("unexpected failover status: %+v", status)
	}
}

func TestManagedRuntimeReturnsAggregateErrorWhenAllEndpointsFail(t *testing.T) {
	t.Parallel()

	store := &stubStateStore{loadState: storage.DefaultState()}
	authState := storage.State{Version: storage.CurrentVersion}
	mr := &managedRuntime{
		opts: Options{
			Listen: ListenOptions{Address: testkit.LocalListenSDK},
			HTTP:   HTTPOptions{Enabled: true},
		},
		store: store,
		auth:  &stubAuthEnsurer{result: authState},
		status: Status{
			HTTPEnabled: true,
		},
	}
	mr.selectFn = func(context.Context, storage.State) (endpointSelection, []storage.Node, error) {
		candidates := []discovery.Candidate{
			{Address: testkit.WarpIPv4Primary443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
			{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
		}
		return endpointSelection{Primary: candidates[0], Candidates: candidates}, nil, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		return &stubClientRuntimeAdapter{
			status:   runtimeStatus(testkit.LocalListenSDK, endpoint, true, false, false),
			startErr: errors.New("connect failed"),
		}, nil
	}

	err := mr.Start(context.Background())
	if err == nil {
		t.Fatal("expected aggregate failure when all endpoints fail")
	}
	for _, want := range []string{testkit.WarpIPv4Primary443, testkit.WarpIPv4Alt443} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected aggregate error to mention %q, got %v", want, err)
		}
	}
	if len(store.saved) != 0 {
		t.Fatalf("expected no state save on total failure, got %+v", store.saved)
	}
}

func TestManagedRuntimeFailsOverOnReportedEndpointFailure(t *testing.T) {
	t.Parallel()

	store := &stubStateStore{loadState: storage.DefaultState()}
	authState := storage.State{
		Version: storage.CurrentVersion,
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
	}

	firstRuntime := &stubClientRuntimeAdapter{
		status: runtimeStatus(testkit.LocalListenSDK, testkit.WarpIPv4Primary443, true, true, false),
	}
	secondRuntime := &stubClientRuntimeAdapter{
		status: runtimeStatus(testkit.LocalListenSDK, testkit.WarpIPv4Alt443, true, true, false),
	}

	mr := &managedRuntime{
		opts: Options{
			Listen: ListenOptions{Address: testkit.LocalListenSDK},
			HTTP:   HTTPOptions{Enabled: true},
			SOCKS5: SOCKS5Options{Enabled: true},
		},
		store: store,
		auth:  &stubAuthEnsurer{result: authState},
		status: Status{
			HTTPEnabled:   true,
			SOCKS5Enabled: true,
		},
	}
	mr.selectFn = func(context.Context, storage.State) (endpointSelection, []storage.Node, error) {
		candidates := []discovery.Candidate{
			{Address: testkit.WarpIPv4Primary443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
			{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true},
		}
		return endpointSelection{Primary: candidates[0], Candidates: candidates}, []storage.Node{
			{ID: "node-1", EndpointV4: testkit.WarpIPv4Primary443},
			{ID: "node-2", EndpointV4: testkit.WarpIPv4Alt443},
		}, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		switch endpoint {
		case testkit.WarpIPv4Primary443:
			return firstRuntime, nil
		case testkit.WarpIPv4Alt443:
			return secondRuntime, nil
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil, nil
		}
	}

	if err := mr.Start(context.Background()); err != nil {
		t.Fatalf("expected initial start success, got %v", err)
	}

	mr.handleFailureEvent(failure.Event{
		Component: failure.ComponentSession,
		Endpoint:  testkit.WarpIPv4Primary443,
		Err:       errors.New("ensure connect-ip ready: protocol mismatch"),
	})

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mr.Status().Endpoint == testkit.WarpIPv4Alt443 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	status := mr.Status()
	if status.Endpoint != testkit.WarpIPv4Alt443 || !status.Running {
		t.Fatalf("expected runtime to fail over to second endpoint, got %+v", status)
	}
	if firstRuntime.closeCalls == 0 {
		t.Fatalf("expected first runtime to be closed during failover, got %+v", firstRuntime)
	}
	if secondRuntime.startCalls == 0 {
		t.Fatalf("expected second runtime to start during failover, got %+v", secondRuntime)
	}
	if got := store.saved[len(store.saved)-1].SelectedNode; got != testkit.WarpIPv4Alt443 {
		t.Fatalf("expected failover to persist second endpoint, got %q", got)
	}
}

type stubSDKRuntime struct {
	startCalls int
	closeCalls int
	status     Status
}

func (s *stubSDKRuntime) Start(context.Context) error {
	s.startCalls++
	return nil
}

func (s *stubSDKRuntime) Run() error { return nil }

func (s *stubSDKRuntime) Close() error {
	s.closeCalls++
	s.status.Running = false
	return nil
}
func (s *stubSDKRuntime) HealthCheck(context.Context) error { return nil }

func (s *stubSDKRuntime) Status() Status {
	return s.status
}

func (s *stubSDKRuntime) ListenAddress() string {
	return s.status.ListenAddress
}

type stubAuthEnsurer struct {
	result storage.State
}

func (s *stubAuthEnsurer) Ensure(context.Context) (auth.Result, error) {
	return auth.Result{
		Action: auth.ActionRegister,
		State:  s.result,
	}, nil
}

type stubStateStore struct {
	loadState storage.State
	saved     []storage.State
}

func (s *stubStateStore) Load() (storage.State, error) {
	return s.loadState, nil
}

func (s *stubStateStore) Save(state storage.State) error {
	s.saved = append(s.saved, state)
	return nil
}

type stubClientRuntimeAdapter struct {
	status     Status
	startErr   error
	startCalls int
	closeCalls int
}

func (s *stubClientRuntimeAdapter) Start(context.Context) error {
	s.startCalls++
	return s.startErr
}
func (s *stubClientRuntimeAdapter) Run() error { return nil }
func (s *stubClientRuntimeAdapter) Close() error {
	s.closeCalls++
	s.status.Running = false
	return nil
}
func (s *stubClientRuntimeAdapter) HealthCheck(context.Context) error { return nil }
func (s *stubClientRuntimeAdapter) Status() Status                    { return s.status }
func (s *stubClientRuntimeAdapter) ListenAddress() string             { return s.status.ListenAddress }

func runtimeStatus(listen, endpoint string, httpEnabled, socksEnabled, tunEnabled bool) Status {
	return Status{
		Running:       true,
		ListenAddress: listen,
		Endpoint:      endpoint,
		HTTPEnabled:   httpEnabled,
		SOCKS5Enabled: socksEnabled,
		TUNEnabled:    tunEnabled,
	}
}

type extraSDKRuntime struct {
	startErr   error
	runErr     error
	closeErr   error
	healthErr  error
	status     Status
	listen     string
	startCalls int
	runCalls   int
	closeCalls int
}

func (s *extraSDKRuntime) Start(context.Context) error       { s.startCalls++; return s.startErr }
func (s *extraSDKRuntime) Run() error                        { s.runCalls++; return s.runErr }
func (s *extraSDKRuntime) Close() error                      { s.closeCalls++; return s.closeErr }
func (s *extraSDKRuntime) HealthCheck(context.Context) error { return s.healthErr }
func (s *extraSDKRuntime) Status() Status                    { return s.status }
func (s *extraSDKRuntime) ListenAddress() string             { return s.listen }

type extraAuthEnsurer struct {
	result authResult
	err    error
}

type authResult struct {
	Action string
	State  storage.State
}

func (s *extraAuthEnsurer) Ensure(context.Context) (authResult, error) { return s.result, s.err }

type extraStore struct {
	saved   storage.State
	saveErr error
}

func (s *extraStore) Load() (storage.State, error)   { return storage.State{}, nil }
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

type localHTTPStarter struct {
	listenAddress string
	state         string
}

func (s localHTTPStarter) Start(context.Context) error                           { return nil }
func (s localHTTPStarter) StartWithListener(context.Context, net.Listener) error { return nil }
func (s localHTTPStarter) Stop(context.Context) error                            { return nil }
func (s localHTTPStarter) Close() error                                          { return nil }
func (s localHTTPStarter) State() string                                         { return s.state }
func (s localHTTPStarter) Stats() internalconfig.Stats                           { return internalconfig.Stats{} }
func (s localHTTPStarter) ListenAddress() string                                 { return s.listenAddress }

type failingStateStore struct{ err error }

func (s *failingStateStore) Load() (storage.State, error) { return storage.DefaultState(), nil }
func (s *failingStateStore) Save(storage.State) error     { return s.err }

func TestSDKLayoutRemovesMigratedTopLevelDirs(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, name := range []string{"cloudflare", "observe", "session"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Fatalf("expected migrated top-level dir %q to be removed", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "proxy")); err == nil {
		t.Fatal("expected migrated top-level dir \"proxy\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "tun")); err == nil {
		t.Fatal("expected migrated top-level dir \"tun\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "datapath")); err == nil {
		t.Fatal("expected migrated top-level dir \"datapath\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "types")); err == nil {
		t.Fatal("expected migrated top-level dir \"types\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "config")); err == nil {
		t.Fatal("expected migrated top-level dir \"config\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "contracts")); err == nil {
		t.Fatal("expected internal/contracts to be folded into target internal packages")
	}
	for _, name := range []string{"http.go", "socks5.go", "tun.go", "runtime.go"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Fatalf("expected legacy root wrapper file %q to be removed", name)
		}
	}
}

func TestSDKLayoutStopsUsingTopLevelSessionInProductionPaths(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		"sdk_runtime.go",
		filepath.Join("internal", "runtime", "factories.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(data), `"github.com/skye-z/amz/session"`) {
			t.Fatalf("expected %s to stop importing top-level session package", rel)
		}
	}
}

func TestInternalManagersStopUsingTypesSanitizers(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		filepath.Join("internal", "runtime", "http_manager.go"),
		filepath.Join("internal", "runtime", "socks5_manager.go"),
		filepath.Join("internal", "runtime", "tun_manager.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, "types.SanitizeText") || strings.Contains(text, "types.SanitizeError") {
			t.Fatalf("expected %s to stop using top-level types sanitizers", rel)
		}
	}
}

func TestInternalSessionCloudflareStopsUsingTopLevelTypes(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "internal", "session", "cloudflare.go"))
	if err != nil {
		t.Fatalf("read internal/session/cloudflare.go: %v", err)
	}
	if strings.Contains(string(data), `"github.com/skye-z/amz/types"`) {
		t.Fatal("expected internal/session/cloudflare.go to stop using top-level types")
	}
}

func TestConfigStopsUsingTopLevelTypes(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	if strings.Contains(string(data), `"github.com/skye-z/amz/types"`) {
		t.Fatal("expected internal/config/config.go to stop using top-level types")
	}
}

func TestProductionCodeStopsUsingTopLevelConfigPackage(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		"sdk_runtime.go",
		filepath.Join("internal", "runtime", "factories.go"),
		filepath.Join("internal", "runtime", "http_manager.go"),
		filepath.Join("internal", "runtime", "socks5_manager.go"),
		filepath.Join("internal", "runtime", "tun_manager.go"),
		filepath.Join("internal", "session", "cloudflare.go"),
		filepath.Join("internal", "session", "connect_stream.go"),
		filepath.Join("internal", "session", "connectip.go"),
		filepath.Join("internal", "session", "core_tunnel_dialer.go"),
		filepath.Join("internal", "session", "datapath.go"),
		filepath.Join("internal", "session", "quic.go"),
		filepath.Join("internal", "transport", "datapath.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, `"github.com/skye-z/amz/config"`) {
			t.Fatalf("expected %s to stop importing top-level config package", rel)
		}
		if !strings.Contains(text, `"github.com/skye-z/amz/internal/config"`) {
			t.Fatalf("expected %s to import internal/config", rel)
		}
	}
}

func TestManagedRuntimeEmitsStructuredLifecycleLogs(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	store := &stubStateStore{loadState: storage.DefaultState()}
	authState := storage.State{
		Version:  storage.CurrentVersion,
		DeviceID: "device-123",
		Token:    "token-123",
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
		NodeCache: []storage.Node{
			{ID: "node-1", EndpointV4: testkit.WarpIPv4Alt443},
		},
	}
	runtime := &stubClientRuntimeAdapter{
		status: runtimeStatus(testkit.LocalListenSDK, testkit.WarpIPv4Alt443, true, true, false),
	}
	mr := &managedRuntime{
		opts: Options{
			Listen: ListenOptions{Address: testkit.LocalListenSDK},
			HTTP:   HTTPOptions{Enabled: true},
			SOCKS5: SOCKS5Options{Enabled: true},
			Logger: logger,
		},
		store: store,
		auth:  &stubAuthEnsurer{result: authState},
		status: Status{
			HTTPEnabled:   true,
			SOCKS5Enabled: true,
		},
	}
	mr.selectFn = func(context.Context, storage.State) (endpointSelection, []storage.Node, error) {
		candidate := discovery.Candidate{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed, Available: true, WarpEnabled: true}
		return endpointSelection{Primary: candidate, Candidates: []discovery.Candidate{candidate}}, authState.NodeCache, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		return runtime, nil
	}

	if err := mr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := mr.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}

	output := logger.String()
	expectedEndpoint := fmt.Sprintf("endpoint=%q", testkit.WarpIPv4Alt443)
	expectedListen := fmt.Sprintf("listen_address=%q", testkit.LocalListenSDK)
	for _, want := range []string{
		"[START]",
		"[REGISTER]",
		"[SELECT]",
		"[STATE]",
		"[BUILD]",
		"[CONNECT]",
		"[CLOSE]",
		"starting managed runtime",
		"registration state ready",
		"selected endpoint",
		expectedEndpoint,
		expectedListen,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected logs to contain %q, got:\n%s", want, output)
		}
	}
}

func TestLogEventUsesReadableActionFormat(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	logEvent(logger, "managed_runtime", "endpoint.select.success",
		field("endpoint", testkit.WarpIPv4Alt443),
		field("source", "fixed"),
	)

	output := logger.String()
	expectedEndpoint := fmt.Sprintf("endpoint=%q", testkit.WarpIPv4Alt443)
	for _, want := range []string{
		"[SELECT]",
		"selected endpoint",
		expectedEndpoint,
		"source=\"fixed\"",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got %q", want, output)
		}
	}
	if strings.Contains(output, "component=") || strings.Contains(output, "event=") {
		t.Fatalf("expected readable log line, got %q", output)
	}
}

func TestPhaseLoggerPrintsTimestampBeforeAction(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	withAction(logger, "INIT").Printf("initialized")

	output := logger.String()
	if !strings.Contains(output, " [INIT] initialized") {
		t.Fatalf("expected timestamp before action prefix, got %q", output)
	}
	if strings.HasPrefix(output, "[INIT]") {
		t.Fatalf("expected log line to start with timestamp, got %q", output)
	}
}

func TestBaseKernelConfigFromStateCarriesPhaseLogger(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	cfg := baseKernelConfigFromState(storage.State{}, testkit.WarpIPv4Alt443, "warp.cloudflare.com", "http", testkit.LocalListenSDK, withAction(logger, "PROXY"))
	if cfg.Logger == nil {
		t.Fatal("expected base kernel config to carry logger")
	}

	cfg.Logger.Printf("http proxy start: listen=%s endpoint=%s", testkit.LocalListenSDK, testkit.WarpIPv4Alt443)
	output := logger.String()
	if !strings.Contains(output, "[PROXY]") {
		t.Fatalf("expected proxy phase prefix, got %q", output)
	}
}

type capturingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *capturingLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *capturingLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func TestLoggingProberEmitsPerCandidateDiagnostics(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	base := discovery.NewStaticProber(map[string]discovery.ProbeResult{
		testkit.WarpIPv4Alt443: {
			Address:     testkit.WarpIPv4Alt443,
			Latency:     5 * time.Millisecond,
			Available:   true,
			WarpEnabled: true,
		},
	})

	wrapped := newLoggingProber(logger, base)
	results := wrapped.Probe([]discovery.Candidate{
		{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed},
	})
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}

	output := logger.String()
	for _, want := range []string{
		"[SELECT]",
		"probing candidate",
		"probe finished",
		"candidate=\"" + testkit.WarpIPv4Alt443 + "\"",
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
		Address: testkit.WarpIPv4Alt443,
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
		"candidate=\"" + testkit.WarpIPv4Alt443 + "\"",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

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

var tunSelectionGlobalsMu sync.Mutex

func TestTUNCandidateCheckerRequiresConnectIPReady(t *testing.T) {
	tunSelectionGlobalsMu.Lock()
	defer tunSelectionGlobalsMu.Unlock()

	state := storage.State{
		Certificate: storage.Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
		Interface: storage.InterfaceAddresses{
			V4: testkit.TunIPv4Addr,
			V6: testkit.TunIPv6Addr,
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
	ok, err := checker.CheckWarp(context.Background(), discovery.Candidate{Address: testkit.WarpIPv4Alt4500, Source: discovery.SourceFixed})
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
	tunSelectionGlobalsMu.Lock()
	defer tunSelectionGlobalsMu.Unlock()

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
	ok, err := checker.CheckWarp(ctx, discovery.Candidate{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed})
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
	tunSelectionGlobalsMu.Lock()
	defer tunSelectionGlobalsMu.Unlock()

	state := storage.State{
		NodeCache: []storage.Node{{
			Host:       testkit.WarpHostPrimary,
			EndpointV4: testkit.WarpIPv4Primary443,
			EndpointV6: testkit.WarpIPv6Primary443,
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
	if err == nil {
		if selection.Primary.Address == "" {
			t.Fatal("expected selected candidate")
		}
		if len(selection.Candidates) == 0 {
			t.Fatal("expected ordered candidate list")
		}
		if selection.Candidates[0].Address != selection.Primary.Address {
			t.Fatalf("expected primary candidate to lead ordered list, got primary=%q list=%+v", selection.Primary.Address, selection.Candidates)
		}
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
		{Address: testkit.WarpIPv4RangeProbe, Source: discovery.SourceAuto},
		{Address: testkit.WarpHostProxy443, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv4Primary443, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv4Alt443, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv4Alt500, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv4Alt1701, Source: discovery.SourceFixed},
		{Address: testkit.WarpIPv4Alt4500, Source: discovery.SourceFixed},
	}

	got := prioritizeTUNCandidates(candidates)
	wantPrefix := []string{
		testkit.WarpIPv4Alt4500,
		testkit.WarpIPv4Alt500,
		testkit.WarpIPv4Alt1701,
		testkit.WarpIPv4Alt443,
	}
	for i, want := range wantPrefix {
		if got[i].Address != want {
			t.Fatalf("expected candidate %d to be %q, got %+v", i, want, got)
		}
	}
}
