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
	clientRuntimeHTTPBody        = "http-ok"
	clientRuntimeTestTUNName     = "igara-test0"

	errHTTPManagerCreate  = "expected http manager creation success, got %v"
	errSOCKSManagerCreate = "expected socks manager creation success, got %v"
	errClientRuntimeNew   = "expected client runtime creation success, got %v"
	errRuntimeStart       = "expected start success, got %v"
	errSOCKSGreetingWrite = "expected socks greeting write success, got %v"
	errGreetingReply      = "expected greeting reply %v, got %v"
)

func TestClientRuntimeMuxesHTTPAndSOCKS5OnSinglePort(t *testing.T) {
	t.Parallel()

	runtime := newClientRuntimeWithHTTPAndSOCKS(t, clientRuntimeHTTPBody)
	defer runtime.Close()

	listenAddress := startClientRuntime(t, runtime)
	assertRuntimeHTTPBody(t, listenAddress, clientRuntimeHTTPBody)
	assertRuntimeSOCKSEcho(t, listenAddress, clientRuntimeEchoPayload)
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
		t.Fatalf(errHTTPManagerCreate, err)
	}

	tunnel, err := internalruntime.NewTunManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: clientRuntimeTestTUNName},
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
		t.Fatalf(errClientRuntimeNew, err)
	}

	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf(errRuntimeStart, err)
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
		t.Fatalf(errHTTPManagerCreate, err)
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
		t.Fatalf(errSOCKSManagerCreate, err)
	}
	tunnel, err := internalruntime.NewTunManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: clientRuntimeTestTUNName},
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
		t.Fatalf(errClientRuntimeNew, err)
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
		t.Fatalf(errClientRuntimeNew, err)
	}
	err = runtime.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "http unhealthy") {
		t.Fatalf("expected http health error, got %v", err)
	}
}

func TestClientRuntimeCanHotSwapProxyBackends(t *testing.T) {
	t.Parallel()

	runtime1 := newClientRuntimeWithHTTPAndSOCKS(t, "old")
	defer runtime1.Close()
	listenAddress := startClientRuntime(t, runtime1)

	runtime2 := newClientRuntimeWithHTTPAndSOCKS(t, "new")
	defer runtime2.Close()

	if !runtime1.HotSwapProxyBackendsFrom(runtime2) {
		t.Fatal("expected hot swap to succeed")
	}

	assertRuntimeHTTPBody(t, listenAddress, "new")
	assertRuntimeSOCKSGreeting(t, listenAddress, " after hot swap")
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
		TUN:            config.TUNConfig{Name: clientRuntimeTestTUNName},
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
		t.Fatalf(errSOCKSGreetingWrite, err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingReply); err != nil {
		t.Fatalf("expected socks greeting reply success, got %v", err)
	}
	if want := []byte{0x05, 0x00}; string(greetingReply) != string(want) {
		t.Fatalf(errGreetingReply, want, greetingReply)
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

func newClientRuntimeWithHTTPAndSOCKS(t *testing.T, httpBody string) *internalruntime.ClientRuntime {
	t.Helper()

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: testkit.LocalListenZero,
		HTTP:          internalruntime.NewHTTPRuntime(newTestHTTPManager(t, httpBody)),
		SOCKS5:        internalruntime.NewSOCKS5Runtime(newTestSOCKSManager(t)),
	})
	if err != nil {
		t.Fatalf(errClientRuntimeNew, err)
	}
	return runtime
}

func newTestHTTPManager(t *testing.T, body string) *internalruntime.HTTPManager {
	t.Helper()

	manager, err := internalruntime.NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf(errHTTPManagerCreate, err)
	}
	manager.SetHTTPRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}))
	return manager
}

func newTestSOCKSManager(t *testing.T) *internalruntime.SOCKS5Manager {
	t.Helper()

	manager, err := internalruntime.NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf(errSOCKSManagerCreate, err)
	}
	manager.SetStreamManager(echoStreamOpener{})
	return manager
}

func startClientRuntime(t *testing.T, runtime *internalruntime.ClientRuntime) string {
	t.Helper()

	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf(errRuntimeStart, err)
	}
	listenAddress := runtime.ListenAddress()
	if listenAddress == "" || listenAddress == testkit.LocalListenZero {
		t.Fatalf("expected resolved listen address, got %q", listenAddress)
	}
	return listenAddress
}

func assertRuntimeHTTPBody(t *testing.T, listenAddress, wantBody string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, clientRuntimeHTTPResourceURL, nil)
	if err != nil {
		t.Fatalf("expected request construction success, got %v", err)
	}
	conn := dialRuntimeConn(t, listenAddress, "expected http dial success, got %v")
	writeHTTPRequest(t, conn, req, "expected http request write success, got %v")
	resp := readHTTPResponse(t, conn, req)
	gotBody := readResponseBody(t, resp)
	if gotBody != wantBody {
		t.Fatalf("expected http body %q, got %q", wantBody, gotBody)
	}
}

func assertRuntimeSOCKSEcho(t *testing.T, listenAddress, payload string) {
	t.Helper()

	conn := dialRuntimeConn(t, listenAddress, "expected socks dial success, got %v")
	defer conn.Close()
	assertRuntimeSOCKSGreetingWithConn(t, conn, "")
	writeSOCKSConnectRequest(t, conn, "expected socks connect request write success, got %v")
	assertSOCKSConnectReply(t, conn)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("expected socks payload write success, got %v", err)
	}
	echoReply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoReply); err != nil {
		t.Fatalf("expected socks payload echo success, got %v", err)
	}
	if string(echoReply) != payload {
		t.Fatalf("expected echo payload %q, got %q", payload, string(echoReply))
	}
}

func assertRuntimeSOCKSGreeting(t *testing.T, listenAddress, suffix string) {
	t.Helper()

	conn := dialRuntimeConn(t, listenAddress, "expected socks dial success"+suffix+", got %v")
	defer conn.Close()
	assertRuntimeSOCKSGreetingWithConn(t, conn, suffix)
}

func dialRuntimeConn(t *testing.T, listenAddress, errFormat string) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatalf(errFormat, err)
	}
	return conn
}

func writeHTTPRequest(t *testing.T, conn net.Conn, req *http.Request, errFormat string) {
	t.Helper()

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		t.Fatalf(errFormat, err)
	}
}

func readHTTPResponse(t *testing.T, conn net.Conn, req *http.Request) *http.Response {
	t.Helper()

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("expected http response read success, got %v", err)
	}
	return resp
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("expected http response body read success, got %v", err)
	}
	return string(body)
}

func assertRuntimeSOCKSGreetingWithConn(t *testing.T, conn net.Conn, suffix string) {
	t.Helper()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf(errSOCKSGreetingWrite, err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingReply); err != nil {
		t.Fatalf("expected socks greeting reply success%s, got %v", suffix, err)
	}
	if want := []byte{0x05, 0x00}; string(greetingReply) != string(want) {
		t.Fatalf(errGreetingReply, want, greetingReply)
	}
}

func writeSOCKSConnectRequest(t *testing.T, conn net.Conn, errFormat string) {
	t.Helper()

	connectRequest := buildSOCKSDomainConnectRequest(testkit.TestDomain, 80)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf(errFormat, err)
	}
}

func assertSOCKSConnectReply(t *testing.T, conn net.Conn) {
	t.Helper()

	connectReply, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatalf("expected socks connect reply success, got %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("expected socks connect success reply, got %v", connectReply)
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
