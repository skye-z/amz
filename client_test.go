package amz

import (
	"context"
	"testing"

	"github.com/skye-z/amz/internal/auth"
	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
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
	if client.opts.Listen.Address != "127.0.0.1:9811" {
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
			ListenAddress: "127.0.0.1:9811",
			Endpoint:      "162.159.198.2:443",
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
	if client.ListenAddress() != "127.0.0.1:9811" {
		t.Fatalf("expected listen address from runtime, got %q", client.ListenAddress())
	}
	status := client.Status()
	if !status.Running || !status.Registered || status.Endpoint != "162.159.198.2:443" {
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
			Listen: ListenOptions{Address: "127.0.0.1:9811"},
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
	mr.selectFn = func(context.Context, storage.State) (discovery.Candidate, []storage.Node, error) {
		return discovery.Candidate{Address: "162.159.198.2:443"}, []storage.Node{
			{ID: "node-1", EndpointV4: "162.159.198.2:443"},
		}, nil
	}
	mr.buildFn = func(endpoint string, state storage.State) (sdkRuntime, error) {
		return &stubClientRuntimeAdapter{status: runtimeStatus("127.0.0.1:9811", endpoint, true, true, false)}, nil
	}

	err := mr.Start(context.Background())
	if err != nil {
		t.Fatalf("expected managed runtime start success, got %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("expected one state save, got %d", len(store.saved))
	}
	if store.saved[0].SelectedNode != "162.159.198.2:443" {
		t.Fatalf("expected selected node persisted, got %+v", store.saved[0])
	}
	status := mr.Status()
	if !status.Running || status.ListenAddress != "127.0.0.1:9811" || status.Endpoint != "162.159.198.2:443" || !status.Registered {
		t.Fatalf("unexpected managed runtime status: %+v", status)
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
	status Status
}

func (s *stubClientRuntimeAdapter) Start(context.Context) error { return nil }
func (s *stubClientRuntimeAdapter) Run() error                  { return nil }
func (s *stubClientRuntimeAdapter) Close() error {
	s.status.Running = false
	return nil
}
func (s *stubClientRuntimeAdapter) Status() Status        { return s.status }
func (s *stubClientRuntimeAdapter) ListenAddress() string { return s.status.ListenAddress }

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
