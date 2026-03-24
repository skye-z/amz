package kernel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

type recordingHTTPDialer struct {
	mu      sync.Mutex
	calls   []string
	latency time.Duration
	dialer  net.Dialer
}

func (d *recordingHTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.latency > 0 {
		timer := time.NewTimer(d.latency)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
	d.mu.Lock()
	d.calls = append(d.calls, address)
	d.mu.Unlock()
	return d.dialer.DialContext(ctx, network, address)
}

func (d *recordingHTTPDialer) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

type fakeStreamDialer struct {
	open func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error)
}

func (d fakeStreamDialer) DialStream(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
	return d.open(ctx, h3conn, quic, h3, opts)
}

type trackingConn struct {
	net.Conn
	closeCount atomic.Int32
	closed     chan struct{}
	onClose    func()
}

func newTrackingConn(conn net.Conn, onClose func()) *trackingConn {
	return &trackingConn{Conn: conn, closed: make(chan struct{}), onClose: onClose}
}

func (c *trackingConn) Close() error {
	if c.closeCount.Add(1) == 1 {
		if c.onClose != nil {
			c.onClose()
		}
		close(c.closed)
	}
	return c.Conn.Close()
}

func (c *trackingConn) Closed() <-chan struct{} {
	return c.closed
}

func newTestHTTPProxyManager(t *testing.T) *HTTPProxyManager {
	t.Helper()
	manager, err := NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	return manager
}

func newReadyStreamManagerForTest(open func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error)) *ConnectStreamManager {
	return &ConnectStreamManager{
		state:   StreamStateReady,
		quic:    QUICOptions{Endpoint: "127.0.0.1:0"},
		h3:      HTTP3Options{Authority: "example.test:443"},
		dialer:  fakeStreamDialer{open: open},
		streams: map[string]*activeStream{},
	}
}

// 验证 HTTP 代理会执行真实 CONNECT 并通过共享 dialer 建立双向字节流。
func TestHTTPProxyManagerCONNECTRuntime(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected upstream listen success, got %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	manager, err := NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	dialer := &recordingHTTPDialer{latency: 5 * time.Millisecond}
	manager.SetHTTPDialer(dialer)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Addr().String(), upstream.Addr().String()); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected status line read success, got %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 connect response, got %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("expected header read success, got %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected tunneled write success, got %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("expected tunneled read success, got %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected echoed payload ping, got %q", string(buf))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("expected proxy connection close success, got %v", err)
	}

	if len(dialer.Calls()) != 1 || dialer.Calls()[0] != upstream.Addr().String() {
		t.Fatalf("expected shared dialer to dial upstream once, got %+v", dialer.Calls())
	}
	stats := waitHTTPProxyStats(t, manager, func(s types.Stats) bool {
		return s.TxBytes >= 4 && s.RxBytes >= 4
	})
	if stats.TxBytes < 4 || stats.RxBytes < 4 {
		t.Fatalf("expected connect transfer stats, got %+v", stats)
	}
	if stats.HandshakeLatency <= 0 {
		t.Fatalf("expected handshake latency recorded, got %+v", stats)
	}
}

// 验证 HTTP 代理会通过同一共享 dialer 完成普通 HTTP 转发。
func TestHTTPProxyManagerForwardRuntime(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Upstream", "ok")
		_, _ = io.WriteString(w, "pong")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("expected upstream url parse success, got %v", err)
	}

	manager, err := NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	dialer := &recordingHTTPDialer{latency: 5 * time.Millisecond}
	manager.SetHTTPDialer(dialer)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	proxyURL, err := url.Parse("http://" + manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy url parse success, got %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("expected proxied get success, got %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("expected response body read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if string(body) != "pong" {
		t.Fatalf("expected body pong, got %q", string(body))
	}
	if resp.Header.Get("X-Upstream") != "ok" {
		t.Fatalf("expected upstream header, got %+v", resp.Header)
	}
	if len(dialer.Calls()) == 0 || dialer.Calls()[0] != targetURL.Host {
		t.Fatalf("expected shared dialer to reach upstream host %q, got %+v", targetURL.Host, dialer.Calls())
	}
	stats := manager.Stats()
	if stats.RxBytes < len(body) {
		t.Fatalf("expected response bytes recorded, got %+v", stats)
	}
	if stats.HandshakeLatency <= 0 {
		t.Fatalf("expected handshake latency recorded, got %+v", stats)
	}
}

func TestHTTPProxyManagerCONNECTStreamRelay(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	releaseUpstream := make(chan struct{})

	streamMgr := newReadyStreamManagerForTest(func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		if opts.TargetHost != "relay.example.com" || opts.TargetPort != "443" {
			t.Fatalf("expected stream target relay.example.com:443, got %s:%s", opts.TargetHost, opts.TargetPort)
		}
		return newTrackingConn(upstreamClient, nil), &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, 5 * time.Millisecond, nil
	})

	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(upstreamServer, buf); err != nil {
			return
		}
		if string(buf) != "ping" {
			return
		}
		_, _ = upstreamServer.Write([]byte("pong"))
		<-releaseUpstream
	}()

	manager := newTestHTTPProxyManager(t)
	manager.SetStreamManager(streamMgr)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, reader := openHTTPConnectTunnel(t, manager.ListenAddress(), "relay.example.com:443")
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected tunneled write success, got %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("expected tunneled read success, got %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("expected pong from stream relay, got %q", string(buf))
	}

	stats := waitHTTPProxyStats(t, manager, func(s types.Stats) bool {
		return s.TxBytes >= 4 && s.RxBytes >= 4
	})
	if stats.TxBytes < 4 || stats.RxBytes < 4 {
		t.Fatalf("expected stream relay stats, got %+v", stats)
	}
	if streamMgr.StreamEndpoint("relay.example.com", "443") == nil {
		t.Fatalf("expected active stream endpoint to be tracked")
	}

	close(releaseUpstream)
	if err := conn.Close(); err != nil {
		t.Fatalf("expected client close success, got %v", err)
	}
	waitForHTTPCondition(t, time.Second, func() bool {
		return streamMgr.StreamEndpoint("relay.example.com", "443") == nil
	}, "expected stream to be removed after client close")
}

func TestHTTPProxyManagerCONNECTStreamClosesBothSidesOnUpstreamExit(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	closedByProxy := make(chan struct{})
	streamMgr := newReadyStreamManagerForTest(func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		return newTrackingConn(upstreamClient, func() {
			close(closedByProxy)
		}), &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, 5 * time.Millisecond, nil
	})

	go func() {
		defer upstreamServer.Close()
		_, _ = upstreamServer.Write([]byte("bye"))
	}()

	manager := newTestHTTPProxyManager(t)
	manager.SetStreamManager(streamMgr)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, reader := openHTTPConnectTunnel(t, manager.ListenAddress(), "close.example.com:443")
	defer conn.Close()

	buf := make([]byte, 3)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("expected stream payload read success, got %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("expected upstream payload bye, got %q", string(buf))
	}

	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("expected read deadline set success, got %v", err)
	}
	_, err := reader.ReadByte()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected tunnel EOF after upstream exit, got %v", err)
	}

	select {
	case <-closedByProxy:
	case <-time.After(time.Second):
		t.Fatal("expected upstream stream connection to be closed by proxy")
	}

	waitForHTTPCondition(t, time.Second, func() bool {
		return streamMgr.StreamEndpoint("close.example.com", "443") == nil
	}, "expected stream to be removed after upstream exit")

	stats := waitHTTPProxyStats(t, manager, func(s types.Stats) bool {
		return s.RxBytes >= 3
	})
	if stats.RxBytes < 3 {
		t.Fatalf("expected downstream bytes to be recorded, got %+v", stats)
	}
	if stats.TxBytes != 0 {
		t.Fatalf("expected no upstream tx bytes after one-way close, got %+v", stats)
	}
}

func TestHTTPProxyManagerCONNECTStreamOpenFailure(t *testing.T) {
	streamMgr := newReadyStreamManagerForTest(func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		return nil, &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("failed"))}, 0, errors.New("open stream boom")
	})

	manager := newTestHTTPProxyManager(t)
	manager.SetStreamManager(streamMgr)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT broken.example.com:443 HTTP/1.1\r\nHost: broken.example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected failure status line read success, got %v", err)
	}
	if !strings.Contains(statusLine, "502") {
		t.Fatalf("expected 502 connect response, got %q", statusLine)
	}
}

func TestHTTPProxyManagerConnectViaStreamClosesUpstreamOnWriteFailure(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	closedByProxy := make(chan struct{})
	streamMgr := newReadyStreamManagerForTest(func(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		return newTrackingConn(upstreamClient, func() { close(closedByProxy) }), &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, time.Millisecond, nil
	})

	manager := newTestHTTPProxyManager(t)
	handler := &httpProxyHandler{manager: manager}

	req := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Host = "broken.example.com:443"
	recorder := httptest.NewRecorder()

	handler.handleConnectViaStream(recorder, req, streamMgr)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when hijacking is unsupported, got %d", recorder.Code)
	}
	select {
	case <-closedByProxy:
	case <-time.After(time.Second):
		t.Fatal("expected upstream stream to close on early connect failure")
	}
	_ = upstreamServer.Close()
}

func openHTTPConnectTunnel(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("expected proxy dial success, got %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		t.Fatalf("expected connect request write success, got %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("expected status line read success, got %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		_ = conn.Close()
		t.Fatalf("expected 200 connect response, got %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatalf("expected header read success, got %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, reader
}

func waitForHTTPCondition(t *testing.T, timeout time.Duration, fn func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

func waitHTTPProxyStats(t *testing.T, manager *HTTPProxyManager, fn func(types.Stats) bool) types.Stats {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := manager.Stats()
		if fn(stats) {
			return stats
		}
		time.Sleep(10 * time.Millisecond)
	}
	return manager.Stats()
}
