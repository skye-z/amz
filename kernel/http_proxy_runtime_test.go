package kernel_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
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

	manager, err := kernel.NewHTTPProxyManager(config.KernelConfig{
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

	manager, err := kernel.NewHTTPProxyManager(config.KernelConfig{
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

func waitHTTPProxyStats(t *testing.T, manager *kernel.HTTPProxyManager, fn func(types.Stats) bool) types.Stats {
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
