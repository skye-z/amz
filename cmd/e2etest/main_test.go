package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skye-z/amz"
	"github.com/skye-z/amz/internal/testkit"
)

const (
	testStatePath           = "./state.json"
	testRunListenAddress    = "127.0.0.1:19811"
	testFailureListenAddr   = "127.0.0.1:1"
	testIPField             = "ip"
	testExpectedExitCodeOne = "expected exit code 1, got %d"
	testFetchIPBody         = `{"ip":"` + testkit.TestIPv4Echo + `","city":"A","country":"B","connection":{"org":"C"}}`
)

func TestBuildClientOptionsInjectsLoggerAndEndpoint(t *testing.T) {
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)

	opts := buildClientOptions(testkit.LocalListenSDK, testStatePath, testkit.WarpIPv4Primary443, logger)

	if opts.Logger == nil {
		t.Fatal("expected logger to be injected into amz options")
	}
	if opts.Transport.Endpoint != testkit.WarpIPv4Primary443 {
		t.Fatalf("expected endpoint override to be kept, got %q", opts.Transport.Endpoint)
	}
	if !opts.HTTP.Enabled || !opts.SOCKS5.Enabled {
		t.Fatalf("expected http and socks5 to be enabled, got %+v", opts)
	}
}

func TestBuildClientOptionsCanEnableTUNOnly(t *testing.T) {
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)

	opts := buildClientOptionsForModes(testkit.LocalListenSDK, testStatePath, "", logger, false, false, true)

	if !opts.TUN.Enabled {
		t.Fatal("expected tun to be enabled")
	}
	if opts.HTTP.Enabled || opts.SOCKS5.Enabled {
		t.Fatalf("expected http/socks5 to be disabled, got %+v", opts)
	}
}

func TestShouldRunModeFlags(t *testing.T) {
	tests := []struct {
		name      string
		skipHTTP  bool
		skipSOCKS bool
		skipTUN   bool
		http      bool
		socks     bool
		tun       bool
	}{
		{name: "run all", http: true, socks: true, tun: true},
		{name: "skip tun", skipTUN: true, http: true, socks: true, tun: false},
		{name: "skip http", skipHTTP: true, http: false, socks: true, tun: true},
		{name: "skip socks", skipSOCKS: true, http: true, socks: false, tun: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http, socks, tun := shouldRunModes(tt.skipHTTP, tt.skipSOCKS, tt.skipTUN)
			if http != tt.http || socks != tt.socks || tun != tt.tun {
				t.Fatalf("expected (%v,%v,%v), got (%v,%v,%v)", tt.http, tt.socks, tt.tun, http, socks, tun)
			}
		})
	}
}

func TestDefaultIPTransportDisablesConnectionReuse(t *testing.T) {
	transport := defaultIPTransport()
	if transport == nil {
		t.Fatal("expected direct transport")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("expected keepalives disabled to avoid reusing pre-tunnel direct connections")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("expected http2 disabled for deterministic direct/tun checks")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchIPSuccessAndHeaders(t *testing.T) {
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != ipAPI {
			t.Fatalf("unexpected url: %s", req.URL.String())
		}
		if got := req.Header.Get("User-Agent"); got != "amz-e2etest/1.0" {
			t.Fatalf("unexpected user-agent: %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(testFetchIPBody))}, nil
	})
	ip, raw, err := fetchIP(context.Background(), transport)
	if err != nil {
		t.Fatalf("expected fetch success, got %v", err)
	}
	if ip != testkit.TestIPv4Echo || raw[testIPField].(string) != testkit.TestIPv4Echo {
		t.Fatalf("unexpected fetch result: %s %+v", ip, raw)
	}
}

func TestFetchIPErrorBranches(t *testing.T) {
	cases := []struct {
		name string
		rt   http.RoundTripper
	}{
		{name: "request error", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("boom") })},
		{name: "bad json", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`oops`))}, nil
		})},
		{name: "missing ip", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"country":"x"}`))}, nil
		})},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := fetchIP(context.Background(), tt.rt); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestProxyTransportHelpersAndLogger(t *testing.T) {
	httpTransport := httpProxyTransport("127.0.0.1:8080")
	if httpTransport == nil || httpTransport.Proxy == nil {
		t.Fatal("expected http proxy transport with proxy func")
	}
	socksTransport, err := socks5ProxyTransport("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("expected socks transport creation success, got %v", err)
	}
	if socksTransport == nil {
		t.Fatal("expected socks transport")
	}
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)
	logger.Printf("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected logger output, got %q", buf.String())
	}
}

func TestPrintHelpers(t *testing.T) {
	oldStdout := captureStdout(t)
	oldStderr := captureStderr(t)
	printBanner("Banner")
	printStep(2, "Step")
	printInfo("info %s", "x")
	printPass("pass %s", "x")
	printFail("fail %s", "x")
	printIPInfo("TAG", testkit.PublicDNSV4, map[string]any{"city": "A", "country": "B", "org": "C"})
	stdout := oldStdout()
	stderr := oldStderr()
	if !strings.Contains(stdout, "Banner") || !strings.Contains(stdout, "[PASS]") || !strings.Contains(stdout, "[TAG] IP") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "[FAIL]") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("expected stdout pipe success, got %v", err)
	}
	os.Stdout = w
	return func() string {
		_ = w.Close()
		os.Stdout = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("expected stderr pipe success, got %v", err)
	}
	os.Stderr = w
	return func() string {
		_ = w.Close()
		os.Stderr = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}

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
	cfg := runConfig{listen: testFailureListenAddr, statePath: testStatePath, timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: true}
	deps := runDeps{
		fetchIP: func(context.Context, transportRoundTripper) (string, map[string]any, error) {
			return "", nil, errors.New("direct failed")
		},
		newClient: (&fakeFactory{}).NewClient,
		sleep: func(time.Duration) {
			// No-op: skip sleeping in tests.
		},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf(testExpectedExitCodeOne, code)
	}
}

func TestRunE2EReturnsFailureWhenClientCreationFails(t *testing.T) {
	cfg := runConfig{listen: testFailureListenAddr, statePath: testStatePath, timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: false}
	deps := runDeps{
		fetchIP: func(context.Context, transportRoundTripper) (string, map[string]any, error) {
			return testkit.PublicDNSV4, map[string]any{testIPField: testkit.PublicDNSV4}, nil
		},
		newClient: (&fakeFactory{err: errors.New("create failed")}).NewClient,
		sleep: func(time.Duration) {
			// No-op: skip sleeping in tests.
		},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf(testExpectedExitCodeOne, code)
	}
}

func TestRunE2EReturnsSuccessWhenAllModesPass(t *testing.T) {
	cfg := runConfig{listen: testRunListenAddress, statePath: testStatePath, timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: true}
	factory := &fakeFactory{clients: []*fakeClient{
		{status: amz.Status{Running: true, ListenAddress: testRunListenAddress, Endpoint: testkit.WarpIPv4Alt500, Registered: true, HTTPEnabled: true, SOCKS5Enabled: true}},
		{status: amz.Status{Running: true, Endpoint: testkit.WarpIPv4Alt500, Registered: true, TUNEnabled: true}},
	}}
	ips := []string{testkit.PublicDNSV4, testkit.PublicDNSV4Alt, testkit.TestIPv4Echo, testkit.TestIPv4Private}
	deps := runDeps{
		fetchIP: func(_ context.Context, _ transportRoundTripper) (string, map[string]any, error) {
			ip := ips[0]
			ips = ips[1:]
			return ip, map[string]any{testIPField: ip}, nil
		},
		newClient: factory.NewClient,
		sleep: func(time.Duration) {
			// No-op: skip sleeping in tests.
		},
	}
	if code := runE2E(cfg, deps); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunE2EReturnsFailureWhenHTTPCheckFails(t *testing.T) {
	cfg := runConfig{listen: testRunListenAddress, statePath: testStatePath, timeout: time.Second, runHTTP: true, runSOCKS5: true, runTUN: false}
	factory := &fakeFactory{clients: []*fakeClient{{status: amz.Status{Running: true, ListenAddress: testRunListenAddress, Endpoint: testkit.WarpIPv4Alt500, Registered: true, HTTPEnabled: true, SOCKS5Enabled: true}}}}
	calls := 0
	deps := runDeps{
		fetchIP: func(_ context.Context, _ transportRoundTripper) (string, map[string]any, error) {
			calls++
			switch calls {
			case 1:
				return testkit.PublicDNSV4, map[string]any{testIPField: testkit.PublicDNSV4}, nil
			case 2:
				return "", nil, errors.New("http failed")
			default:
				return testkit.TestIPv4Echo, map[string]any{testIPField: testkit.TestIPv4Echo}, nil
			}
		},
		newClient: factory.NewClient,
		sleep: func(time.Duration) {
			// No-op: skip sleeping in tests.
		},
	}
	if code := runE2E(cfg, deps); code != 1 {
		t.Fatalf(testExpectedExitCodeOne, code)
	}
}
