package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/testkit"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	httpConnectTarget  = testkit.TestDomain + ":443"
	httpConnectRequest = "CONNECT " + httpConnectTarget + " HTTP/1.1\r\nHost: " + httpConnectTarget + "\r\n\r\n"
	echoPayload        = "ping"
)

func TestHTTPManagerConnectFallsBackToDialerWhenStreamOpenFails(t *testing.T) {
	t.Parallel()

	manager, err := NewHTTPManager(config.KernelConfig{
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
	manager.SetHTTPDialer(echoHTTPDialer{})
	manager.SetStreamManager(failingHTTPStreamOpener{})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response, got %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte(echoPayload)); err != nil {
		t.Fatalf("expected payload write success, got %v", err)
	}
	reply := make([]byte, len(echoPayload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected payload echo success, got %v", err)
	}
	if got := string(reply); got != echoPayload {
		t.Fatalf("expected echo payload %q, got %q", echoPayload, got)
	}
}

func TestHTTPManagerReportsFailureWhenStreamOpenFails(t *testing.T) {
	t.Parallel()

	manager, err := NewHTTPManager(config.KernelConfig{
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
	manager.SetHTTPDialer(echoHTTPDialer{})
	manager.SetStreamManager(failingHTTPStreamOpener{})
	var reported atomic.Bool
	manager.SetFailureReporter(func(failure.Event) {
		reported.Store(true)
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response, got %d", resp.StatusCode)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && !reported.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !reported.Load() {
		t.Fatal("expected stream open failure to be reported")
	}
}

func TestHTTPManagerRetriesCurrentConnectAfterFailureReporterSwapsBackend(t *testing.T) {
	t.Parallel()

	manager, err := NewHTTPManager(config.KernelConfig{
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
	manager.SetHTTPDialer(failingHTTPDialer{err: context.DeadlineExceeded})
	manager.SetStreamManager(failingHTTPStreamOpener{})
	manager.SetFailureReporter(func(failure.Event) {
		manager.SetHTTPDialer(echoHTTPDialer{})
		manager.SetStreamManager(echoHTTPStreamOpener{})
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected retried connect response success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response after retry, got %d", resp.StatusCode)
	}
}

func TestHTTPManagerReconnectsStreamAfterBackendRefresh(t *testing.T) {
	t.Parallel()

	manager, err := NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: 100 * time.Millisecond,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}
	manager.SetHTTPDialer(failingHTTPDialer{err: context.DeadlineExceeded})
	manager.SetStreamManager(protocolErrorHTTPStreamOpener{err: context.DeadlineExceeded})
	manager.SetFailureReporter(func(failure.Event) {
		manager.SetStreamManager(echoHTTPStreamOpener{})
		time.Sleep(20 * time.Millisecond)
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response after backend refresh, got %d", resp.StatusCode)
	}
}

func TestHTTPManagerConnectFallbackUsesFreshTimeoutContext(t *testing.T) {
	t.Parallel()

	manager, err := NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: 50 * time.Millisecond,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected http manager creation success, got %v", err)
	}
	manager.SetHTTPDialer(checkingHTTPDialer{})
	manager.SetStreamManager(blockingHTTPStreamOpener{})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response after fallback, got %d", resp.StatusCode)
	}
}

type failingHTTPStreamOpener struct{}

func (failingHTTPStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("stream unauthorized")
}

type protocolErrorHTTPStreamOpener struct {
	err error
}

func (o protocolErrorHTTPStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("cloudflare compatibility error: operation=connect-stream quirk=protocol_error: %w", o.err)
}

type blockingHTTPStreamOpener struct{}

func (blockingHTTPStreamOpener) OpenStream(ctx context.Context, _ string, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

type checkingHTTPDialer struct{}

func (checkingHTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

type echoHTTPDialer struct{}

func (echoHTTPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

type failingHTTPDialer struct {
	err error
}

func (d failingHTTPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func TestHealthCheckSpecRunNilCheck(t *testing.T) {
	if err := (HealthCheckSpec{}).Run(context.Background()); err != nil {
		t.Fatalf("expected nil health check success, got %v", err)
	}
}

func TestMuxListenerDispatchesProtocolsAndCloses(t *testing.T) {
	ln, err := net.Listen("tcp", testkit.LocalListenZero)
	if err != nil {
		t.Fatalf("expected listen success, got %v", err)
	}
	mux, err := NewMuxListener(ln)
	if err != nil {
		t.Fatalf("expected mux creation success, got %v", err)
	}
	defer mux.Close()

	httpConn, err := net.Dial("tcp", mux.ListenAddress())
	if err != nil {
		t.Fatalf("expected http dial success, got %v", err)
	}
	defer httpConn.Close()
	if _, err := httpConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("expected http write success, got %v", err)
	}
	httpAccepted, err := mux.HTTPListener().Accept()
	if err != nil {
		t.Fatalf("expected http accept success, got %v", err)
	}
	defer httpAccepted.Close()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(httpAccepted, buf); err != nil {
		t.Fatalf("expected replayed prefix, got %v", err)
	}
	if string(buf) != "GET" {
		t.Fatalf("expected GET prefix, got %q", string(buf))
	}

	socksConn, err := net.Dial("tcp", mux.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer socksConn.Close()
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("expected socks write success, got %v", err)
	}
	socksAccepted, err := mux.SOCKS5Listener().Accept()
	if err != nil {
		t.Fatalf("expected socks accept success, got %v", err)
	}
	defer socksAccepted.Close()
	buf = make([]byte, 3)
	if _, err := io.ReadFull(socksAccepted, buf); err != nil {
		t.Fatalf("expected replayed socks bytes, got %v", err)
	}
	if buf[0] != 0x05 {
		t.Fatalf("expected socks version byte, got %v", buf)
	}

	if got := mux.Addr().String(); got == "" {
		t.Fatal("expected mux addr")
	}
	if err := mux.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
}

func TestMuxHelpersRejectInvalidInputs(t *testing.T) {
	if _, err := NewMuxListener(nil); err == nil {
		t.Fatal("expected nil listener error")
	}
	if _, err := sniffProxyProtocol(0x01); !errors.Is(err, errUnsupportedProxyProtocol) {
		t.Fatalf("expected unsupported protocol error, got %v", err)
	}
	wrapped := &prefixedConn{Conn: nil, reader: bufio.NewReader(strings.NewReader("abc"))}
	buf := make([]byte, 2)
	if n, err := wrapped.Read(buf); err != nil || n != 2 || string(buf) != "ab" {
		t.Fatalf("expected buffered read success, got n=%d err=%v buf=%q", n, err, string(buf))
	}
}

func TestClientRuntimeRunReuseAndReleaseListeners(t *testing.T) {
	httpRuntime := NewHTTPRuntime(localHTTPStarter{listenAddress: testkit.LocalListenZero, state: config.StateIdle})
	socksRuntime := NewSOCKS5Runtime(localSOCKSStarter{listenAddress: testkit.LocalListenZero, state: config.StateIdle})
	prev, err := NewClientRuntime(ClientRuntimeOptions{ListenAddress: testkit.LocalListenZero, HTTP: httpRuntime, SOCKS5: socksRuntime})
	if err != nil {
		t.Fatalf("expected previous runtime creation success, got %v", err)
	}
	mux, err := ListenMux(testkit.LocalListenZero)
	if err != nil {
		t.Fatalf("expected mux creation success, got %v", err)
	}
	defer mux.Close()
	prev.mux = mux
	prev.listen = mux.ListenAddress()

	next, err := NewClientRuntime(ClientRuntimeOptions{
		HTTP:   NewHTTPRuntime(localHTTPStarter{listenAddress: testkit.LocalListenZero, state: config.StateIdle}),
		SOCKS5: NewSOCKS5Runtime(localSOCKSStarter{listenAddress: testkit.LocalListenZero, state: config.StateIdle}),
	})
	if err != nil {
		t.Fatalf("expected next runtime creation success, got %v", err)
	}
	next.ReuseProxyListenersFrom(prev)
	if next.mux == nil || next.listen != prev.listen {
		t.Fatalf("expected proxy listeners reused, got mux=%v listen=%q", next.mux, next.listen)
	}
	next.ReleaseProxyListeners()
	if next.mux != nil {
		t.Fatal("expected released proxy listeners")
	}

	runRuntime, err := NewClientRuntime(ClientRuntimeOptions{HTTP: NewHTTPRuntime(localHTTPStarter{listenAddress: testkit.LocalListenSDK, state: config.StateIdle})})
	if err != nil {
		t.Fatalf("expected runtime creation success, got %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- runRuntime.Run() }()
	time.Sleep(10 * time.Millisecond)
	if err := runRuntime.Close(); err != nil {
		t.Fatalf("expected runtime close success, got %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected runtime run success, got %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("expected runtime run to stop after close")
	}
}

func TestClientRuntimeHelpersAndClosers(t *testing.T) {
	httpOnly := NewHTTPRuntime(localHTTPStarter{listenAddress: "127.0.0.1:8080", state: config.StateIdle})
	socksOnly := NewSOCKS5Runtime(localSOCKSStarter{listenAddress: "127.0.0.1:1080", state: config.StateIdle})
	if got := resolvedRuntimeListenAddress(httpOnly, nil); got != "127.0.0.1:8080" {
		t.Fatalf("unexpected resolved http listen address: %q", got)
	}
	if got := resolvedRuntimeListenAddress(nil, socksOnly); got != "127.0.0.1:1080" {
		t.Fatalf("unexpected resolved socks listen address: %q", got)
	}
	if got := resolvedRuntimeListenAddress(nil, nil); got != "" {
		t.Fatalf("expected empty resolved listen address, got %q", got)
	}

	calls := 0
	stopClosers([]func() error{
		func() error { calls = calls*10 + 1; return nil },
		func() error { calls = calls*10 + 2; return nil },
	})
	if calls != 21 {
		t.Fatalf("expected reverse closer order 21, got %d", calls)
	}
}

func TestHTTPAndSOCKSRuntimeWrappersAndTunHelpers(t *testing.T) {
	httpRuntime := NewHTTPRuntime(nil)
	if httpRuntime != nil {
		t.Fatal("expected nil HTTP runtime when manager missing")
	}
	socksRuntime := NewSOCKS5Runtime(nil)
	if socksRuntime != nil {
		t.Fatal("expected nil SOCKS runtime when manager missing")
	}
	if got := NormalizeTUNName("  amz0  "); got != "amz0" {
		t.Fatalf("unexpected normalized tun name: %q", got)
	}
	if NewTUNRuntime(nil) != nil || NewTUNRuntimeWithHealth(nil, nil) != nil {
		t.Fatal("expected nil tun runtime for nil manager")
	}
}

func TestTunManagerAndBootstrapManagerBranches(t *testing.T) {
	if _, err := NewTunManager(nil); err == nil {
		t.Fatal("expected nil tun config error")
	}
	manager, err := NewTunManager(&config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, TUN: config.TUNConfig{Name: "igara0"}})
	if err != nil {
		t.Fatalf("expected tun manager creation success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected idempotent start success, got %v", err)
	}
	if manager.Logger() != nil {
		t.Fatal("expected nil logger by default")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if got := manager.State(); got != config.StateStopped {
		t.Fatalf("expected stopped state, got %q", got)
	}

	if _, err := NewBootstrapTUNManager(nil, &stubTUNBootstrap{}); err == nil {
		t.Fatal("expected nil bootstrap config error")
	}
	if _, err := NewBootstrapTUNManager(&config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, TUN: config.TUNConfig{Name: "igara0"}}, nil); err == nil {
		t.Fatal("expected nil bootstrap dependency error")
	}
	bootstrap := &stubTUNBootstrap{}
	bootMgr, err := NewBootstrapTUNManager(&config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, TUN: config.TUNConfig{Name: "igara0"}}, bootstrap)
	if err != nil {
		t.Fatalf("expected bootstrap manager creation success, got %v", err)
	}
	if err := bootMgr.Start(context.Background()); err != nil {
		t.Fatalf("expected bootstrap start success, got %v", err)
	}
	if err := bootMgr.Start(context.Background()); err != nil {
		t.Fatalf("expected bootstrap idempotent start success, got %v", err)
	}
	if err := bootMgr.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop success, got %v", err)
	}
}

func TestRuntimeFactoriesAndHealthWrappers(t *testing.T) {
	if _, err := NewHTTPRuntimeFromConfig(config.KernelConfig{}); err == nil {
		t.Fatal("expected invalid http config error")
	}
	if _, err := NewSOCKS5RuntimeFromConfig(nil); err == nil {
		t.Fatal("expected nil socks config error")
	}
	if _, err := NewTUNRuntimeFromConfig(nil); err == nil {
		t.Fatal("expected nil tun config error")
	}
	if _, err := NewHTTPRuntimeFromSharedDialer(config.KernelConfig{}, nil, nil); err == nil {
		t.Fatal("expected invalid shared http config error")
	}
	if _, err := NewSOCKS5RuntimeFromSharedDialer(nil, nil, nil); err == nil {
		t.Fatal("expected invalid shared socks config error")
	}
	if _, err := NewTUNRuntimeFromBootstrap(nil, nil, nil, nil); err == nil {
		t.Fatal("expected invalid tun bootstrap config error")
	}

	httpRT := NewHTTPRuntime(localHTTPStarter{listenAddress: testkit.LocalListenSDK, state: config.StateIdle})
	httpRT.SetFailureReporter(func(failure.Event) {})
	if err := httpRT.Start(context.Background()); err != nil {
		t.Fatalf("expected http runtime start success, got %v", err)
	}
	if err := httpRT.Stop(context.Background()); err != nil {
		t.Fatalf("expected http runtime stop success, got %v", err)
	}
	if httpRT.HealthSpec().Mode != HealthCheckModePassiveProxy {
		t.Fatalf("unexpected http health mode: %+v", httpRT.HealthSpec())
	}

	socksRT := NewSOCKS5Runtime(localSOCKSStarter{listenAddress: testkit.LocalListenSOCKS, state: config.StateIdle})
	socksRT.SetFailureReporter(func(failure.Event) {})
	if err := socksRT.Start(context.Background()); err != nil {
		t.Fatalf("expected socks runtime start success, got %v", err)
	}
	if err := socksRT.Stop(context.Background()); err != nil {
		t.Fatalf("expected socks runtime stop success, got %v", err)
	}

	tunRT := NewTUNRuntime(localTunnel{state: config.StateIdle})
	if err := tunRT.Start(context.Background()); err != nil {
		t.Fatalf("expected tun runtime start success, got %v", err)
	}
	if err := tunRT.Stop(context.Background()); err != nil {
		t.Fatalf("expected tun runtime stop success, got %v", err)
	}
	if tunRT.HealthSpec().Mode != HealthCheckModeActiveTunnel {
		t.Fatalf("unexpected tun health mode: %+v", tunRT.HealthSpec())
	}
}

func TestHTTPManagerUtilityHelpers(t *testing.T) {
	manager, err := NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if manager.State() != config.StateIdle {
		t.Fatalf("expected idle state, got %q", manager.State())
	}
	if manager.ListenAddress() == "" || manager.Snapshot().ListenAddress == "" {
		t.Fatal("expected non-empty listen address snapshot")
	}
	manager.AddReconnect()
	if stats := manager.Stats(); stats.ReconnectCount != 1 {
		t.Fatalf("expected reconnect count 1, got %+v", stats)
	}

	customRT := localRoundTripper(func(*http.Request) (*http.Response, error) { return nil, nil })
	manager.SetHTTPRoundTripper(customRT)
	if got := manager.currentRoundTripper(); got == nil {
		t.Fatal("expected configured round tripper")
	}
	manager.SetHTTPRoundTripper(nil)
	if got := manager.currentRoundTripper(); got == nil {
		t.Fatal("expected fallback round tripper")
	}

	src := http.Header{}
	src.Add("A", "1")
	dst := http.Header{}
	copyHeaders(dst, src)
	if dst.Get("A") != "1" {
		t.Fatalf("expected copied header, got %+v", dst)
	}
	headers := http.Header{"Connection": []string{"keep-alive"}, "Upgrade": []string{"h2c"}}
	removeHopByHopHeaders(headers)
	if headers.Get("Connection") != "" || headers.Get("Upgrade") != "" {
		t.Fatalf("expected hop-by-hop headers removed, got %+v", headers)
	}
	if !isClosedNetworkError(net.ErrClosed) {
		t.Fatal("expected closed network error detection")
	}
	if isClosedNetworkError(errors.New("boom")) {
		t.Fatal("expected generic error not to be treated as closed network error")
	}
	args := sanitizeHTTPArgs([]any{"token=secret", errors.New("bad")})
	if len(args) != 2 {
		t.Fatalf("unexpected sanitized args: %+v", args)
	}
	reader := &countingReadCloser{ReadCloser: io.NopCloser(strings.NewReader("abc"))}
	buf := make([]byte, 2)
	if n, err := reader.Read(buf); err != nil || n != 2 || reader.count != 2 {
		t.Fatalf("unexpected counting reader state: n=%d err=%v count=%d", n, err, reader.count)
	}

	done := make(chan bool, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		manager.mu.Lock()
		manager.cfg.Endpoint = "new-endpoint"
		manager.mu.Unlock()
		done <- true
	}()
	if !manager.waitForBackendRefresh(context.Background(), config.DefaultEndpoint, manager.currentBackendSignature(), 200*time.Millisecond) {
		t.Fatal("expected backend refresh detection")
	}
	<-done
	if manager.waitForEndpointChange(context.Background(), "new-endpoint", 30*time.Millisecond) {
		t.Fatal("expected endpoint change wait to time out when unchanged")
	}
}

func TestHTTPManagerHandleForwardAndRetryBranches(t *testing.T) {
	manager, err := NewHTTPManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: 50 * time.Millisecond,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	handler := &httpHandler{manager: manager}
	manager.SetHTTPDialer(failingHTTPDialer{err: errors.New("dial unavailable")})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	handler.handleForward(recorder, req)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway with failing default transport, got %d", recorder.Code)
	}

	manager.SetHTTPRoundTripper(localRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("roundtrip failed")
	}))
	recorder = httptest.NewRecorder()
	handler.handleForward(recorder, req)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway on roundtrip error, got %d", recorder.Code)
	}

	manager.SetHTTPRoundTripper(localRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Connection": []string{"keep-alive"}, "X-Test": []string{"ok"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	}))
	recorder = httptest.NewRecorder()
	handler.handleForward(recorder, req)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("unexpected forward success response: code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Connection") != "" || recorder.Header().Get("X-Test") != "ok" {
		t.Fatalf("unexpected forwarded headers: %+v", recorder.Header())
	}

	if _, _, retried := manager.retryConnectOnce(context.Background(), "connect-stream", "bad-target", errors.New("boom"), "", ""); !retried {
		t.Fatal("expected retry flag on malformed target branch")
	}

	reported := false
	manager.SetFailureReporter(func(failure.Event) { reported = true })
	manager.reportFailure("op", errors.New("boom"))
	if !reported {
		t.Fatal("expected http failure reporter invocation")
	}
}

func TestSOCKS5ManagerUtilityHelpersAndAuth(t *testing.T) {
	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero, Username: "u", Password: "p"},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	if manager.State() != config.StateIdle || manager.ListenAddress() == "" {
		t.Fatalf("unexpected initial manager state/listen: %q %q", manager.State(), manager.ListenAddress())
	}
	manager.AddReconnect()
	manager.SetUDPAssociateRelay(stubUDPRelay{})
	if snapshot := manager.Snapshot(); snapshot.Username != "u" || snapshot.ListenAddress == "" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if stats := manager.Stats(); stats.ReconnectCount != 1 {
		t.Fatalf("unexpected reconnect stats: %+v", stats)
	}
	args := sanitizeSOCKS5Args([]any{"token=secret", errors.New("bad")})
	if len(args) != 2 {
		t.Fatalf("unexpected sanitized socks args: %+v", args)
	}

	server, client := net.Pipe()
	defer client.Close()
	authDone := make(chan error, 1)
	go func() {
		authDone <- manager.handleUserPassAuth(server)
		server.Close()
	}()
	_, _ = client.Write([]byte{socksAuthVersion, 0x01, 'u', 0x01, 'p'})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("expected auth reply success, got %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("expected auth success reply, got %v", reply)
	}
	if err := <-authDone; err != nil {
		t.Fatalf("expected auth success, got %v", err)
	}

	server, client = net.Pipe()
	defer client.Close()
	authDone = make(chan error, 1)
	go func() {
		authDone <- manager.handleUserPassAuth(server)
		server.Close()
	}()
	_, _ = client.Write([]byte{socksAuthVersion, 0x01, 'x', 0x01, 'y'})
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("expected auth failure reply success, got %v", err)
	}
	if reply[1] != 0x01 {
		t.Fatalf("expected auth failure reply, got %v", reply)
	}
	if err := <-authDone; err == nil {
		t.Fatal("expected auth failure error")
	}

	if _, _, err := parseSOCKSTargetAddress("missing-port"); err == nil {
		t.Fatal("expected malformed socks target error")
	}
	if _, err := readAddressFromConn(bytes.NewReader([]byte{0x00}), 0x09); err == nil {
		t.Fatal("expected unsupported address type error")
	}
	if _, err := readAddress(&bytesReader{0x09}); err == nil {
		t.Fatal("expected unsupported bytesReader address type error")
	}
	done := make(chan struct{}, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		manager.mu.Lock()
		manager.streamManager = localStreamOpener{}
		manager.mu.Unlock()
		done <- struct{}{}
	}()
	if !manager.waitForBackendRefresh(context.Background(), config.DefaultEndpoint, manager.currentBackendSignature(), 200*time.Millisecond) {
		t.Fatal("expected socks backend refresh detection")
	}
	<-done
	done = make(chan struct{}, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		manager.mu.Lock()
		manager.cfg.Endpoint = "new-endpoint"
		manager.mu.Unlock()
		done <- struct{}{}
	}()
	if !manager.waitForEndpointChange(context.Background(), config.DefaultEndpoint, 200*time.Millisecond) {
		t.Fatal("expected socks endpoint change detection")
	}
	<-done
}

func TestSOCKS5ManagerStateSnapshotAndUDPAssociatePaths(t *testing.T) {
	manager, err := NewSOCKS5Manager(&config.KernelConfig{
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
	if manager.State() != config.StateIdle {
		t.Fatalf("expected idle state, got %q", manager.State())
	}
	if snapshot := manager.Snapshot(); snapshot.ListenAddress == "" {
		t.Fatalf("expected snapshot listen address, got %+v", snapshot)
	}

	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.handleUDPAssociate(context.Background(), server)
		server.Close()
	}()
	reply := make([]byte, 10)
	if _, err := io.ReadAtLeast(client, reply, 2); err != nil {
		t.Fatalf("expected udp associate unavailable reply, got %v", err)
	}
	if reply[1] != socksReplyCommandNotSup {
		t.Fatalf("expected command not supported reply, got %v", reply[:2])
	}
	if err := <-errCh; err == nil {
		t.Fatal("expected udp associate unavailable error")
	}
}

func TestSOCKS5ManagerHandleUDPAssociateAndUDPLoop(t *testing.T) {
	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: 100 * time.Millisecond,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero, EnableUDP: true},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected udp listen success, got %v", err)
	}
	defer packetConn.Close()
	relay := &recordingUDPRelay{response: UDPAssociateResponse{SourceAddress: testkit.PublicDNSV4Alt + ":53", Payload: []byte("pong")}}
	manager.mu.Lock()
	manager.udpPacketConn = packetConn
	manager.udpRelay = relay
	manager.associations = make(map[string]*udpAssociation)
	manager.mu.Unlock()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected tcp listen success, got %v", err)
	}
	defer tcpLn.Close()
	tcpAccepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := tcpLn.Accept()
		tcpAccepted <- conn
	}()
	clientConn, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("expected tcp dial success, got %v", err)
	}
	defer clientConn.Close()
	serverConn := <-tcpAccepted

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.handleUDPAssociate(ctx, serverConn)
		serverConn.Close()
	}()
	reply := make([]byte, 64)
	if _, err := io.ReadAtLeast(clientConn, reply, 2); err != nil {
		t.Fatalf("expected udp associate success reply, got %v", err)
	}
	if reply[1] != socksReplySucceeded {
		t.Fatalf("expected udp associate success reply, got %v", reply[:2])
	}
	waitForRuntimeCondition(t, 200*time.Millisecond, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return len(manager.associations) == 1
	})

	manager.runWG.Add(1)
	udpCtx, udpCancel := context.WithCancel(context.Background())
	go manager.udpLoop(udpCtx)
	peerConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected peer udp listen success, got %v", err)
	}
	defer peerConn.Close()
	packet, err := buildSOCKSUDPDatagram(testkit.PublicDNSV4Alt+":53", []byte("ping"))
	if err != nil {
		t.Fatalf("expected udp packet build success, got %v", err)
	}
	if _, err := peerConn.WriteTo(packet, packetConn.LocalAddr()); err != nil {
		t.Fatalf("expected udp packet send success, got %v", err)
	}
	respBuf := make([]byte, 128)
	_ = peerConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := peerConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected udp response, got %v", err)
	}
	target, payload, err := parseSOCKSUDPDatagram(respBuf[:n])
	if err != nil {
		t.Fatalf("expected parse udp response success, got %v", err)
	}
	if target != relay.response.SourceAddress || string(payload) != "pong" {
		t.Fatalf("unexpected udp response target=%q payload=%q", target, string(payload))
	}
	udpCancel()
	_ = packetConn.Close()
	manager.runWG.Wait()
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected udp associate to end with context canceled, got %v", err)
	}
}

func TestHTTPAndSOCKSRuntimeStatsAccessors(t *testing.T) {
	httpRT := NewHTTPRuntime(localHTTPStarter{listenAddress: testkit.LocalListenSDK, state: config.StateIdle})
	if got := httpRT.Stats(); got.StartCount != 0 {
		t.Fatalf("unexpected http runtime stats: %+v", got)
	}
	if spec := httpRT.HealthSpec(); spec.Component != "http" {
		t.Fatalf("unexpected http health spec: %+v", spec)
	}
	socksRT := NewSOCKS5Runtime(localSOCKSStarter{listenAddress: testkit.LocalListenSOCKS, state: config.StateIdle})
	if got := socksRT.Stats(); got.StartCount != 0 {
		t.Fatalf("unexpected socks runtime stats: %+v", got)
	}
	if spec := socksRT.HealthSpec(); spec.Component != "socks5" {
		t.Fatalf("unexpected socks health spec: %+v", spec)
	}
	var nilHTTP *HTTPRuntime
	nilHTTP.SetFailureReporter(func(failure.Event) {})
	var nilSOCKS *SOCKS5Runtime
	nilSOCKS.SetFailureReporter(func(failure.Event) {})
}

func TestHTTPHandleConnectViaStreamAndHelpers(t *testing.T) {
	manager, err := NewHTTPManager(config.KernelConfig{
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
	manager.SetStreamManager(localStreamOpener{})
	host, port, err := parseHTTPConnectTarget("example.com")
	if err != nil || host != "example.com" || port != "443" {
		t.Fatalf("unexpected parsed target host=%q port=%q err=%v", host, port, err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected connect response 200, got %d", resp.StatusCode)
	}
}

func TestSOCKSAddressReadersAndNegotiationBranches(t *testing.T) {
	if host, err := readAddressFromConn(bytes.NewReader([]byte{1, 2, 3, 4}), socksAtypIPv4); err != nil || host != "1.2.3.4" {
		t.Fatalf("unexpected ipv4 read result host=%q err=%v", host, err)
	}
	if host, err := readAddressFromConn(bytes.NewReader(append([]byte{3}, []byte("abc")...)), socksAtypDomain); err != nil || host != "abc" {
		t.Fatalf("unexpected domain read result host=%q err=%v", host, err)
	}
	ipv6raw := make([]byte, 16)
	ipv6raw[15] = 1
	if host, err := readAddressFromConn(bytes.NewReader(ipv6raw), socksAtypIPv6); err != nil || !strings.Contains(host, "::1") {
		t.Fatalf("unexpected ipv6 read result host=%q err=%v", host, err)
	}
	r := bytesReader(append([]byte{3, 3}, []byte("abc")...))
	if host, err := readAddress(&r); err != nil || host != "abc" {
		t.Fatalf("unexpected bytesReader domain result host=%q err=%v", host, err)
	}
	r = bytesReader(append([]byte{socksAtypIPv4}, []byte{1, 2, 3, 4}...))
	if host, err := readAddress(&r); err != nil || host != "1.2.3.4" {
		t.Fatalf("unexpected bytesReader ipv4 result host=%q err=%v", host, err)
	}

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero, Username: "u", Password: "p"},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.negotiate(server)
		server.Close()
	}()
	_, _ = client.Write([]byte{0x04, 0x01, 0x00})
	if err := <-errCh; err == nil {
		t.Fatal("expected unsupported socks version error")
	}

	server, client = net.Pipe()
	defer client.Close()
	errCh = make(chan error, 1)
	go func() {
		errCh <- manager.negotiate(server)
		server.Close()
	}()
	_, _ = client.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("expected no acceptable reply read success, got %v", err)
	}
	if reply[1] != socksMethodNoAcceptable {
		t.Fatalf("expected no acceptable auth reply, got %v", reply)
	}
	if err := <-errCh; err == nil {
		t.Fatal("expected no acceptable auth error")
	}
}

func TestUpstreamConnectDialerFailureBranches(t *testing.T) {
	writeFailDialer := &recordingDialer{connFactory: func() net.Conn {
		client, server := net.Pipe()
		_ = server.Close()
		return client
	}}
	if _, err := newUpstreamConnectDialer(writeFailDialer, "proxy.local:8080").DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected write/read failure from upstream dialer")
	}

	rejectDialer := &recordingDialer{connFactory: func() net.Conn {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = server.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		}()
		return client
	}}
	if _, err := newUpstreamConnectDialer(rejectDialer, "proxy.local:8080").DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected upstream rejection error")
	}

	plainDialer := &recordingDialer{}
	if err := newUpstreamConnectDialer(plainDialer, "proxy.local:8080").Close(); err != nil {
		t.Fatalf("expected upstream close passthrough success, got %v", err)
	}
}

func TestUpstreamAndDNSDialers(t *testing.T) {
	if _, err := newUpstreamConnectDialer(nil, "proxy").DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected unavailable upstream dialer error")
	}
	base := &recordingDialer{connFactory: func() net.Conn {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			req, _ := http.ReadRequest(bufio.NewReader(server))
			if req != nil {
				_, _ = server.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			}
		}()
		return client
	}}
	upstream := newUpstreamConnectDialer(base, "proxy.local:8080")
	conn, err := upstream.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("expected upstream connect success, got %v", err)
	}
	_ = conn.Close()
	if base.lastAddress != "proxy.local:8080" {
		t.Fatalf("expected upstream target address, got %q", base.lastAddress)
	}
	if err := upstream.Close(); err != nil {
		t.Fatalf("expected upstream close success, got %v", err)
	}
	transport := newUpstreamHTTPTransport("proxy.local:8080", base)
	if transport == nil {
		t.Fatal("expected upstream transport")
	}
	if newUpstreamHTTPTransport("proxy.local:8080", nil) != nil {
		t.Fatal("expected nil upstream transport when dialer missing")
	}

	dnsDialer := NewExportedDNSResolvingDialer(&recordingDialer{})
	if _, err := dnsDialer.DialContext(context.Background(), "tcp", testkit.TestIPv4Echo+":53"); err != nil {
		t.Fatalf("expected direct ip dial success, got %v", err)
	}
	if err := dnsDialer.Close(); err != nil {
		t.Fatalf("expected dns dialer close success, got %v", err)
	}
	if _, err := newDNSResolvingDialer(&recordingDialer{}).DialContext(context.Background(), "tcp", "missing-port"); err == nil {
		t.Fatal("expected split host port error")
	}
}

type captureRuntimeLogger struct{ lines []string }

func (l *captureRuntimeLogger) Printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func TestTunLogSanitizersAndStatsAccessors(t *testing.T) {
	logger := &captureRuntimeLogger{}
	manager, err := NewTunManager(&config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, Logger: logger, TUN: config.TUNConfig{Name: "igara0"}})
	if err != nil {
		t.Fatalf("expected tun manager success, got %v", err)
	}
	manager.logf("secret=%s", "token=abc")
	if len(logger.lines) == 0 {
		t.Fatal("expected tun log output")
	}
	if stats := manager.Stats(); stats.StartCount != 0 || stats.StopCount != 0 {
		t.Fatalf("unexpected tun stats: %+v", stats)
	}
	boot, err := NewBootstrapTUNManager(&config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeTUN, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, Logger: logger, TUN: config.TUNConfig{Name: "igara0"}}, &stubTUNBootstrap{})
	if err != nil {
		t.Fatalf("expected bootstrap manager success, got %v", err)
	}
	boot.logf("secret=%s", "token=abc")
	if stats := boot.Stats(); stats.StartCount != 0 || stats.StopCount != 0 {
		t.Fatalf("unexpected bootstrap stats: %+v", stats)
	}
}

func TestRuntimeWrapperNilAndAccessorBranches(t *testing.T) {
	var httpRT *HTTPRuntime
	if err := httpRT.Close(); err != nil || httpRT.ListenAddress() != "" || httpRT.State() != config.StateStopped {
		t.Fatal("expected nil http runtime helpers to be safe")
	}
	var socksRT *SOCKS5Runtime
	if err := socksRT.Close(); err != nil || socksRT.ListenAddress() != "" || socksRT.State() != config.StateStopped {
		t.Fatal("expected nil socks runtime helpers to be safe")
	}
	var tunRT *TUNRuntime
	if err := tunRT.Close(); err != nil || tunRT.State() != config.StateStopped {
		t.Fatal("expected nil tun runtime helpers to be safe")
	}
	if got := tunRT.Stats(); got.StartCount != 0 {
		t.Fatalf("unexpected nil tun stats: %+v", got)
	}
}

type recordingDialer struct {
	lastNetwork string
	lastAddress string
	closed      atomic.Bool
	connFactory func() net.Conn
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.lastNetwork = network
	d.lastAddress = address
	if d.connFactory != nil {
		return d.connFactory(), nil
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (d *recordingDialer) Close() error {
	d.closed.Store(true)
	return nil
}

type localRoundTripper func(*http.Request) (*http.Response, error)

func (f localRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stubUDPRelay struct{}

func (stubUDPRelay) Exchange(context.Context, UDPAssociateRequest) (UDPAssociateResponse, error) {
	return UDPAssociateResponse{}, nil
}

type recordingUDPRelay struct {
	mu       sync.Mutex
	requests []UDPAssociateRequest
	response UDPAssociateResponse
}

func (r *recordingUDPRelay) Exchange(_ context.Context, req UDPAssociateRequest) (UDPAssociateResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return r.response, nil
}

func waitForRuntimeCondition(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

type localStreamOpener struct{}

func (localStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
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
func (s localHTTPStarter) Stats() config.Stats                                   { return config.Stats{} }
func (s localHTTPStarter) ListenAddress() string                                 { return s.listenAddress }

type localSOCKSStarter struct {
	listenAddress string
	state         string
}

func (s localSOCKSStarter) Start(context.Context) error                           { return nil }
func (s localSOCKSStarter) StartWithListener(context.Context, net.Listener) error { return nil }
func (s localSOCKSStarter) Stop(context.Context) error                            { return nil }
func (s localSOCKSStarter) Close() error                                          { return nil }
func (s localSOCKSStarter) State() string                                         { return s.state }
func (s localSOCKSStarter) Stats() config.Stats                                   { return config.Stats{} }
func (s localSOCKSStarter) ListenAddress() string                                 { return s.listenAddress }

type localTunnel struct{ state string }

func (s localTunnel) Start(context.Context) error { return nil }
func (s localTunnel) Stop(context.Context) error  { return nil }
func (s localTunnel) Close() error                { return nil }
func (s localTunnel) State() string               { return s.state }
func (s localTunnel) Stats() config.Stats         { return config.Stats{} }

func TestNewHTTPRuntimeFromSharedDialerUsesStreamManagerForConnect(t *testing.T) {
	t.Parallel()

	runtime, err := NewHTTPRuntimeFromSharedDialer(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	}, failingSharedDialer{}, echoHTTPStreamOpener{})
	if err != nil {
		t.Fatalf("expected shared http runtime creation success, got %v", err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("expected runtime start success, got %v", err)
	}
	defer runtime.Close()

	conn, err := net.Dial("tcp", runtime.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, httpConnectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response, got %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte(echoPayload)); err != nil {
		t.Fatalf("expected payload write success, got %v", err)
	}
	reply := make([]byte, len(echoPayload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected payload echo success, got %v", err)
	}
	if got := string(reply); got != echoPayload {
		t.Fatalf("expected echo payload %q, got %q", echoPayload, got)
	}
}

type failingSharedDialer struct{}

func (failingSharedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("unexpected fallback dialer usage")
}

type echoHTTPStreamOpener struct{}

func (echoHTTPStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func (echoHTTPStreamOpener) SetDeadline(time.Time) error      { return nil }
func (echoHTTPStreamOpener) SetReadDeadline(time.Time) error  { return nil }
func (echoHTTPStreamOpener) SetWriteDeadline(time.Time) error { return nil }

func TestBootstrapTUNManagerStartInvokesPrepare(t *testing.T) {
	t.Parallel()

	bootstrap := &stubTUNBootstrap{}
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, bootstrap)
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if !bootstrap.prepareCalled {
		t.Fatal("expected Prepare to be called")
	}
	if manager.State() != config.StateRunning {
		t.Fatalf("expected running state, got %q", manager.State())
	}
}

func TestBootstrapTUNManagerCloseInvokesBootstrapClose(t *testing.T) {
	t.Parallel()

	bootstrap := &stubTUNBootstrap{}
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, bootstrap)
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if !bootstrap.closeCalled {
		t.Fatal("expected bootstrap Close to be called")
	}
	if manager.State() != config.StateStopped {
		t.Fatalf("expected stopped state, got %q", manager.State())
	}
}

func TestBootstrapTUNManagerPropagatesPrepareError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("prepare failed")
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, &stubTUNBootstrap{prepareErr: wantErr})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected prepare error %v, got %v", wantErr, err)
	}
}

type stubTUNBootstrap struct {
	prepareCalled bool
	closeCalled   bool
	prepareErr    error
	closeErr      error
}

func (s *stubTUNBootstrap) Prepare(context.Context) error {
	s.prepareCalled = true
	return s.prepareErr
}

func (s *stubTUNBootstrap) Close() error {
	s.closeCalled = true
	return s.closeErr
}

const (
	socksIPv4DNSAddress         = testkit.TestIPv4Echo + ":53"
	socksDomainTLSAddress       = testkit.TestDomain + ":443"
	socksIPv6AltTLSAddress      = "[" + testkit.TestIPv6Doc + "]:8443"
	socksPublicDNSAddress       = testkit.PublicDNSV4Alt + ":53"
	socksInvalidNegativePort    = testkit.TestIPv4Echo + ":-1"
	socksInvalidIPv4PortAddress = testkit.TestIPv4Echo + ":65536"
	socksInvalidDomainPort      = testkit.TestDomain + ":70000"
)

func TestEncodeSOCKSAddressSupportsIPv4DomainAndIPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		atyp    byte
		check   func(*testing.T, []byte)
	}{
		{
			name:    "ipv4",
			address: socksIPv4DNSAddress,
			atyp:    socksAtypIPv4,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:5]).String(); got != testkit.TestIPv4Echo {
					t.Fatalf("expected ipv4 host %s, got %q", testkit.TestIPv4Echo, got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[5:7])); got != 53 {
					t.Fatalf("expected ipv4 port 53, got %d", got)
				}
			},
		},
		{
			name:    "domain",
			address: socksDomainTLSAddress,
			atyp:    socksAtypDomain,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				hostLen := int(encoded[1])
				if got := string(encoded[2 : 2+hostLen]); got != testkit.TestDomain {
					t.Fatalf("expected domain host %s, got %q", testkit.TestDomain, got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[2+hostLen:])); got != 443 {
					t.Fatalf("expected domain port 443, got %d", got)
				}
			},
		},
		{
			name:    "ipv6",
			address: socksIPv6AltTLSAddress,
			atyp:    socksAtypIPv6,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:17]).String(); got != testkit.TestIPv6Doc {
					t.Fatalf("expected ipv6 host %s, got %q", testkit.TestIPv6Doc, got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[17:19])); got != 8443 {
					t.Fatalf("expected ipv6 port 8443, got %d", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := encodeSOCKSAddress(tt.address)
			if err != nil {
				t.Fatalf("expected encode success, got %v", err)
			}
			if encoded[0] != tt.atyp {
				t.Fatalf("expected atyp %#x, got %#x", tt.atyp, encoded[0])
			}
			tt.check(t, encoded)
		})
	}
}

func TestBuildAndParseSOCKSUDPDatagramRoundTrip(t *testing.T) {
	t.Parallel()

	address := socksPublicDNSAddress
	payload := []byte("dns-query")

	packet, err := buildSOCKSUDPDatagram(address, payload)
	if err != nil {
		t.Fatalf("expected build success, got %v", err)
	}
	if !bytes.Equal(packet[:3], []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("expected reserved header prefix, got %v", packet[:3])
	}

	target, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if target != address {
		t.Fatalf("expected target %q, got %q", address, target)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("expected payload %q, got %q", string(payload), string(gotPayload))
	}
}

func TestEncodeSOCKSAddressRejectsOutOfRangePorts(t *testing.T) {
	t.Parallel()

	tests := []string{
		socksInvalidNegativePort,
		socksInvalidIPv4PortAddress,
		socksInvalidDomainPort,
	}

	for _, address := range tests {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			if _, err := encodeSOCKSAddress(address); err == nil {
				t.Fatalf("expected out-of-range port error for %q", address)
			}
		})
	}
}

func TestSOCKS5ManagerStopClosesActiveTCPConnections(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected auth reply success, got %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- manager.Stop(context.Background())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		_ = conn.Close()
		err := <-done
		if err != nil {
			t.Fatalf("expected stop success after unblock, got %v", err)
		}
		t.Fatal("expected Stop to return promptly without waiting for client-side close")
	}
}

func TestSOCKS5ManagerReportsFailureWhenUpstreamDialFails(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.SetDialer(&failingContextDialer{err: io.EOF})
	var reported atomic.Bool
	manager.SetFailureReporter(func(failure.Event) {
		reported.Store(true)
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected greeting read success, got %v", err)
	}
	connectRequest := buildSOCKSDomainConnectRequest(testkit.TestDomain, 443)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadAtLeast(conn, resp, 2); err != nil {
		t.Fatalf("expected connect response, got %v", err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && !reported.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !reported.Load() {
		t.Fatal("expected upstream dial failure to be reported")
	}
}

func TestSOCKS5ManagerRetriesCurrentConnectAfterFailureReporterSwapsBackend(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: testkit.LocalListenZero},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.SetDialer(&failingContextDialer{err: context.DeadlineExceeded})
	manager.SetFailureReporter(func(failure.Event) {
		manager.SetDialer(echoHTTPDialer{})
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected greeting read success, got %v", err)
	}
	connectRequest := buildSOCKSDomainConnectRequest(testkit.TestDomain, 443)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := io.ReadAll(io.LimitReader(conn, 10))
	if err != nil {
		t.Fatalf("expected connect response success, got %v", err)
	}
	if len(resp) < 2 || resp[1] != socksReplySucceeded {
		t.Fatalf("expected socks success reply after retry, got %v", resp)
	}
}

type failingContextDialer struct {
	err error
}

func (d *failingContextDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func buildSOCKSDomainConnectRequest(host string, port uint16) []byte {
	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	return binary.BigEndian.AppendUint16(request, port)
}
