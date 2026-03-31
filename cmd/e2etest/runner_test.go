package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skye-z/amz"
)

type fakeClient struct {
	status   amz.Status
	startErr error
	closeErr error
}

func (c *fakeClient) Start(context.Context) error { return c.startErr }
func (c *fakeClient) Close() error                { return c.closeErr }
func (c *fakeClient) Status() amz.Status          { return c.status }

type fakeFactory struct {
	clients []*fakeClient
	calls   int
	err     error
}

func (f *fakeFactory) NewClient(amz.Options) (clientRuntime, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.clients) {
		return nil, errors.New("no fake client left")
	}
	client := f.clients[f.calls]
	f.calls++
	return client, nil
}

func TestRunE2EReturnsFailureWhenDirectFetchFails(t *testing.T) {
	cfg := runConfig{listen: "127.0.0.1:1", statePath: "./state.json", timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: true}
	deps := runDeps{
		fetchIP: func(context.Context, transportRoundTripper) (string, map[string]any, error) { return "", nil, errors.New("direct failed") },
		newClient: (&fakeFactory{}).NewClient,
		sleep: func(time.Duration) {},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunE2EReturnsFailureWhenClientCreationFails(t *testing.T) {
	cfg := runConfig{listen: "127.0.0.1:1", statePath: "./state.json", timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: false}
	deps := runDeps{
		fetchIP: func(context.Context, transportRoundTripper) (string, map[string]any, error) { return "1.1.1.1", map[string]any{"ip": "1.1.1.1"}, nil },
		newClient: (&fakeFactory{err: errors.New("create failed")}).NewClient,
		sleep: func(time.Duration) {},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunE2EReturnsSuccessWhenAllModesPass(t *testing.T) {
	cfg := runConfig{listen: "127.0.0.1:19811", statePath: "./state.json", timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: true}
	factory := &fakeFactory{clients: []*fakeClient{
		{status: amz.Status{Running: true, ListenAddress: "127.0.0.1:19811", Endpoint: "162.159.198.2:500", Registered: true, HTTPEnabled: true, SOCKS5Enabled: true}},
		{status: amz.Status{Running: true, Endpoint: "162.159.198.2:500", Registered: true, TUNEnabled: true}},
	}}
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	deps := runDeps{
		fetchIP: func(_ context.Context, _ transportRoundTripper) (string, map[string]any, error) {
			ip := ips[0]
			ips = ips[1:]
			return ip, map[string]any{"ip": ip}, nil
		},
		newClient: factory.NewClient,
		sleep: func(time.Duration) {},
	}
	if code := runE2E(cfg, deps); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunE2EReturnsFailureWhenHTTPCheckFails(t *testing.T) {
	cfg := runConfig{listen: "127.0.0.1:19811", statePath: "./state.json", timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: false}
	factory := &fakeFactory{clients: []*fakeClient{{status: amz.Status{Running: true, ListenAddress: "127.0.0.1:19811", Endpoint: "162.159.198.2:500", Registered: true, HTTPEnabled: true, SOCKS5Enabled: true}}}}
	calls := 0
	deps := runDeps{
		fetchIP: func(_ context.Context, _ transportRoundTripper) (string, map[string]any, error) {
			calls++
			switch calls {
			case 1:
				return "1.1.1.1", map[string]any{"ip": "1.1.1.1"}, nil
			case 2:
				return "", nil, errors.New("http failed")
			default:
				return "3.3.3.3", map[string]any{"ip": "3.3.3.3"}, nil
			}
		},
		newClient: factory.NewClient,
		sleep: func(time.Duration) {},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
