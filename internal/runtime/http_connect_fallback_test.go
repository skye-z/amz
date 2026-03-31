package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/testkit"
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
