package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/testkit"
)

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
