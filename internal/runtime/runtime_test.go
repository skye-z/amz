package runtime_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skye-z/amz/internal/config"
	internalruntime "github.com/skye-z/amz/internal/runtime"
	"github.com/skye-z/amz/internal/session"
	"github.com/skye-z/amz/internal/testkit"
)

const (
	clientRuntimeHTTPResourceURL = "http://" + testkit.TestDomain + "/resource"
	clientRuntimeEchoPayload     = "ping"
)

func TestClientRuntimeMuxesHTTPAndSOCKS5OnSinglePort(t *testing.T) {
	t.Parallel()

	httpManager, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}
	httpManager.SetHTTPRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("http-ok")),
		}, nil
	}))

	socksManager, err := internalruntime.NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	socksManager.SetStreamManager(echoStreamOpener{})

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          internalruntime.NewHTTPRuntime(httpManager),
		SOCKS5:        internalruntime.NewSOCKS5Runtime(socksManager),
	})
	if err != nil {
		t.Fatalf("expected client runtime creation success, got %v", err)
	}
	defer runtime.Close()

	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}

	listenAddress := runtime.ListenAddress()
	if listenAddress == "" || listenAddress == testkit.LocalListenZero {
		t.Fatalf("expected resolved listen address, got %q", listenAddress)
	}

	req, err := http.NewRequest(http.MethodGet, clientRuntimeHTTPResourceURL, nil)
	if err != nil {
		t.Fatalf("expected request construction success, got %v", err)
	}
	httpConn, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatalf("expected http dial success, got %v", err)
	}
	if err := req.Write(httpConn); err != nil {
		_ = httpConn.Close()
		t.Fatalf("expected http request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(httpConn), req)
	_ = httpConn.Close()
	if err != nil {
		t.Fatalf("expected http response read success, got %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("expected http response body read success, got %v", err)
	}
	if string(body) != "http-ok" {
		t.Fatalf("expected http body %q, got %q", "http-ok", string(body))
	}

	socksConn, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer socksConn.Close()
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("expected socks greeting write success, got %v", err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetingReply); err != nil {
		t.Fatalf("expected socks greeting reply success, got %v", err)
	}
	if want := []byte{0x05, 0x00}; string(greetingReply) != string(want) {
		t.Fatalf("expected greeting reply %v, got %v", want, greetingReply)
	}
	connectRequest := buildSOCKSDomainConnectRequest(testkit.TestDomain, 80)
	if _, err := socksConn.Write(connectRequest); err != nil {
		t.Fatalf("expected socks connect request write success, got %v", err)
	}
	connectReply, err := readSOCKSReply(socksConn)
	if err != nil {
		t.Fatalf("expected socks connect reply success, got %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("expected socks connect success reply, got %v", connectReply)
	}
	if _, err := socksConn.Write([]byte(clientRuntimeEchoPayload)); err != nil {
		t.Fatalf("expected socks payload write success, got %v", err)
	}
	echoReply := make([]byte, len(clientRuntimeEchoPayload))
	if _, err := io.ReadFull(socksConn, echoReply); err != nil {
		t.Fatalf("expected socks payload echo success, got %v", err)
	}
	if string(echoReply) != clientRuntimeEchoPayload {
		t.Fatalf("expected echo payload %q, got %q", clientRuntimeEchoPayload, string(echoReply))
	}
}

func TestClientRuntimeStartsTUNInParallel(t *testing.T) {
	t.Parallel()

	httpManager, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}

	tunnel, err := internalruntime.NewTunManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	})
	if err != nil {
		t.Fatalf("expected tun runtime creation success, got %v", err)
	}

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          internalruntime.NewHTTPRuntime(httpManager),
		TUN:           internalruntime.NewTUNRuntime(tunnel),
	})
	if err != nil {
		t.Fatalf("expected client runtime creation success, got %v", err)
	}

	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}

	status := runtime.Status()
	if !status.Running || !status.HTTPEnabled || !status.TUNEnabled {
		t.Fatalf("expected running http+tun status, got %+v", status)
	}
	if tunnel.State() != config.StateRunning {
		t.Fatalf("expected tun runtime running, got %q", tunnel.State())
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("expected runtime close success, got %v", err)
	}
	if tunnel.State() != config.StateStopped {
		t.Fatalf("expected tun runtime stopped, got %q", tunnel.State())
	}
}

func TestClientRuntimeHealthCheckRunsAllEnabledComponents(t *testing.T) {
	t.Parallel()

	httpManager, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}
	socksManager, err := internalruntime.NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	tunnel, err := internalruntime.NewTunManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	})
	if err != nil {
		t.Fatalf("expected tun manager creation success, got %v", err)
	}

	httpRuntime := internalruntime.NewHTTPRuntime(httpManager)
	socksRuntime := internalruntime.NewSOCKS5Runtime(socksManager)
	tunRuntime := internalruntime.NewTUNRuntime(tunnel)

	var calls atomic.Int32
	httpRuntime.SetHealthCheck(func(context.Context) error {
		calls.Add(1)
		return nil
	})
	socksRuntime.SetHealthCheck(func(context.Context) error {
		calls.Add(1)
		return nil
	})
	tunRuntime.SetHealthCheck(func(context.Context) error {
		calls.Add(1)
		return nil
	})

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          httpRuntime,
		SOCKS5:        socksRuntime,
		TUN:           tunRuntime,
	})
	if err != nil {
		t.Fatalf("expected client runtime creation success, got %v", err)
	}

	if err := runtime.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected health check success, got %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 component health checks, got %d", calls.Load())
	}
}

func TestClientRuntimeHealthCheckReturnsFirstComponentError(t *testing.T) {
	t.Parallel()

	httpRuntime := internalruntime.NewHTTPRuntime(stubHTTPStarter{listenAddress: testkit.LocalListenSDK, state: config.StateIdle})
	socksRuntime := internalruntime.NewSOCKS5Runtime(stubSOCKSStarter{listenAddress: testkit.LocalListenSOCKS, state: config.StateIdle})
	tunRuntime := internalruntime.NewTUNRuntime(stubTunnel{state: config.StateIdle})
	httpRuntime.SetHealthCheck(func(context.Context) error { return errors.New("http unhealthy") })
	socksRuntime.SetHealthCheck(func(context.Context) error { return nil })
	tunRuntime.SetHealthCheck(func(context.Context) error { return nil })

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		HTTP:   httpRuntime,
		SOCKS5: socksRuntime,
		TUN:    tunRuntime,
	})
	if err != nil {
		t.Fatalf("expected client runtime creation success, got %v", err)
	}
	err = runtime.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "http unhealthy") {
		t.Fatalf("expected http health error, got %v", err)
	}
}

func TestClientRuntimeCanHotSwapProxyBackends(t *testing.T) {
	t.Parallel()

	httpManager1, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}
	httpManager1.SetHTTPRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("old"))}, nil
	}))
	socksManager1, err := internalruntime.NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	socksManager1.SetStreamManager(echoStreamOpener{})

	runtime1, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          internalruntime.NewHTTPRuntime(httpManager1),
		SOCKS5:        internalruntime.NewSOCKS5Runtime(socksManager1),
	})
	if err != nil {
		t.Fatalf("expected first runtime creation success, got %v", err)
	}
	defer runtime1.Close()
	if err := runtime1.Start(context.Background()); err != nil {
		t.Fatalf("expected first runtime start success, got %v", err)
	}
	listenAddress := runtime1.ListenAddress()

	httpManager2, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected second http manager creation success, got %v", err)
	}
	httpManager2.SetHTTPRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("new"))}, nil
	}))
	socksManager2, err := internalruntime.NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected second socks manager creation success, got %v", err)
	}
	socksManager2.SetStreamManager(echoStreamOpener{})

	runtime2, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          internalruntime.NewHTTPRuntime(httpManager2),
		SOCKS5:        internalruntime.NewSOCKS5Runtime(socksManager2),
	})
	if err != nil {
		t.Fatalf("expected second runtime creation success, got %v", err)
	}
	defer runtime2.Close()

	if ok := runtime1.HotSwapProxyBackendsFrom(runtime2); !ok {
		t.Fatal("expected hot swap to succeed")
	}

	req, err := http.NewRequest(http.MethodGet, clientRuntimeHTTPResourceURL, nil)
	if err != nil {
		t.Fatalf("expected request construction success, got %v", err)
	}
	httpConn, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatalf("expected reused http dial success, got %v", err)
	}
	if err := req.Write(httpConn); err != nil {
		_ = httpConn.Close()
		t.Fatalf("expected request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(httpConn), req)
	_ = httpConn.Close()
	if err != nil {
		t.Fatalf("expected http response read success, got %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("expected http response body read success, got %v", err)
	}
	if string(body) != "new" {
		t.Fatalf("expected hot swap response body %q, got %q", "new", string(body))
	}

	socksConn, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatalf("expected socks dial success after hot swap, got %v", err)
	}
	defer socksConn.Close()
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("expected socks greeting write success, got %v", err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetingReply); err != nil {
		t.Fatalf("expected socks greeting reply success after hot swap, got %v", err)
	}
	if want := []byte{0x05, 0x00}; string(greetingReply) != string(want) {
		t.Fatalf("expected greeting reply %v, got %v", want, greetingReply)
	}
}

func TestNewClientRuntimeRejectsEmptyConfig(t *testing.T) {
	t.Parallel()

	_, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{})
	if err == nil {
		t.Fatal("expected configuration error when no runtime is configured")
	}
}

func TestNewHTTPRuntimeFromConfig(t *testing.T) {
	t.Parallel()

	runtime, err := internalruntime.NewHTTPRuntimeFromConfig(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http runtime factory success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil http runtime")
	}
}

func TestNewSOCKS5RuntimeFromBootstrap(t *testing.T) {
	t.Parallel()

	baseCfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
	}
	connectionManager, err := session.NewConnectionManager(baseCfg)
	if err != nil {
		t.Fatalf("expected connection manager success, got %v", err)
	}
	connectIPManager, err := session.NewConnectIPSessionManager(baseCfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager success, got %v", err)
	}

	runtime, err := internalruntime.NewSOCKS5RuntimeFromBootstrap(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	}, connectionManager, connectIPManager, &net.Dialer{Timeout: config.DefaultConnectTimeout})
	if err != nil {
		t.Fatalf("expected socks runtime factory success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil socks runtime")
	}
}

func TestNewTUNRuntimeFromConfig(t *testing.T) {
	t.Parallel()

	runtime, err := internalruntime.NewTUNRuntimeFromConfig(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	})
	if err != nil {
		t.Fatalf("expected tun runtime factory success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil tun runtime")
	}
}

func TestNewHTTPRuntimeAcceptsInterfaceManager(t *testing.T) {
	t.Parallel()

	runtime := internalruntime.NewHTTPRuntime(stubHTTPStarter{listenAddress: testkit.LocalListenSDK, state: config.StateIdle})
	if runtime == nil {
		t.Fatal("expected http runtime from interface manager")
	}
}

func TestNewSOCKS5RuntimeAcceptsInterfaceManager(t *testing.T) {
	t.Parallel()

	runtime := internalruntime.NewSOCKS5Runtime(stubSOCKSStarter{listenAddress: testkit.LocalListenSOCKS, state: config.StateIdle})
	if runtime == nil {
		t.Fatal("expected socks5 runtime from interface manager")
	}
}

func TestNewHTTPRuntimeFromBootstrapExposesReusableSnapshot(t *testing.T) {
	t.Parallel()

	baseCfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
	}
	connectionManager, err := session.NewConnectionManager(baseCfg)
	if err != nil {
		t.Fatalf("expected connection manager success, got %v", err)
	}
	connectIPManager, err := session.NewConnectIPSessionManager(baseCfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager success, got %v", err)
	}

	runtime, err := internalruntime.NewHTTPRuntimeFromBootstrap(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	}, connectionManager, connectIPManager, &net.Dialer{Timeout: config.DefaultConnectTimeout})
	if err != nil {
		t.Fatalf("expected http runtime factory success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil http runtime")
	}
	if runtime.ListenAddress() != testkit.LocalListenZero {
		t.Fatalf("expected initial listen address from bootstrap runtime, got %q", runtime.ListenAddress())
	}
}

func TestNewSOCKS5RuntimeFromSharedDialerUsesStreamManager(t *testing.T) {
	t.Parallel()

	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	}
	streamMgr := echoStreamOpener{}

	runtime, err := internalruntime.NewSOCKS5RuntimeFromSharedDialer(&cfg, nil, streamMgr)
	if err != nil {
		t.Fatalf("expected shared socks runtime factory success, got %v", err)
	}
	if runtime == nil {
		t.Fatal("expected non-nil socks runtime")
	}

	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("expected shared socks runtime start success, got %v", err)
	}
	defer runtime.Close()

	conn, err := net.Dial("tcp", runtime.ListenAddress())
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("expected socks greeting write success, got %v", err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingReply); err != nil {
		t.Fatalf("expected socks greeting reply success, got %v", err)
	}
	if want := []byte{0x05, 0x00}; string(greetingReply) != string(want) {
		t.Fatalf("expected greeting reply %v, got %v", want, greetingReply)
	}
	connectRequest := buildSOCKSDomainConnectRequest(testkit.TestDomain, 80)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf("expected socks connect request write success, got %v", err)
	}
	connectReply, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatalf("expected socks connect reply success, got %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("expected socks connect success reply, got %v", connectReply)
	}
	if _, err := conn.Write([]byte(clientRuntimeEchoPayload)); err != nil {
		t.Fatalf("expected socks payload write success, got %v", err)
	}
	echoReply := make([]byte, len(clientRuntimeEchoPayload))
	if _, err := io.ReadFull(conn, echoReply); err != nil {
		t.Fatalf("expected socks payload echo success, got %v", err)
	}
	if string(echoReply) != clientRuntimeEchoPayload {
		t.Fatalf("expected echo payload %q, got %q", clientRuntimeEchoPayload, string(echoReply))
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type echoStreamOpener struct{}

func (echoStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func buildSOCKSDomainConnectRequest(host string, port uint16) []byte {
	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	return append(request, byte(port>>8), byte(port))
}

func readSOCKSReply(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	reply := append([]byte(nil), header...)
	switch header[3] {
	case 0x01:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		reply = append(reply, buf...)
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return nil, err
		}
		reply = append(reply, size...)
		buf := make([]byte, int(size[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		reply = append(reply, buf...)
	case 0x04:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		reply = append(reply, buf...)
	}
	return reply, nil
}

type stubHTTPStarter struct {
	listenAddress string
	state         string
}

func (s stubHTTPStarter) Start(context.Context) error                           { return nil }
func (s stubHTTPStarter) StartWithListener(context.Context, net.Listener) error { return nil }
func (s stubHTTPStarter) Stop(context.Context) error                            { return nil }
func (s stubHTTPStarter) Close() error                                          { return nil }
func (s stubHTTPStarter) State() string                                         { return s.state }
func (s stubHTTPStarter) Stats() config.Stats                                   { return config.Stats{} }
func (s stubHTTPStarter) ListenAddress() string                                 { return s.listenAddress }

type stubSOCKSStarter struct {
	listenAddress string
	state         string
}

func (s stubSOCKSStarter) Start(context.Context) error                           { return nil }
func (s stubSOCKSStarter) StartWithListener(context.Context, net.Listener) error { return nil }
func (s stubSOCKSStarter) Stop(context.Context) error                            { return nil }
func (s stubSOCKSStarter) Close() error                                          { return nil }
func (s stubSOCKSStarter) State() string                                         { return s.state }
func (s stubSOCKSStarter) Stats() config.Stats                                   { return config.Stats{} }
func (s stubSOCKSStarter) ListenAddress() string                                 { return s.listenAddress }

type stubTunnel struct {
	state string
}

func (s stubTunnel) Start(context.Context) error { return nil }
func (s stubTunnel) Stop(context.Context) error  { return nil }
func (s stubTunnel) Close() error                { return nil }
func (s stubTunnel) State() string               { return s.state }
func (s stubTunnel) Stats() config.Stats         { return config.Stats{} }
