package amz

import (
	"context"
	"testing"
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
