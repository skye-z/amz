package amz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/auth"
	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
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
