package amz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
)

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
