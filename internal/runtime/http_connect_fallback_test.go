package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/skye-z/amz/internal/config"
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
		HTTP:           config.HTTPConfig{ListenAddress: "127.0.0.1:0"},
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

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("expected connect response read success, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response, got %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected payload write success, got %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected payload echo success, got %v", err)
	}
	if got := string(reply); got != "ping" {
		t.Fatalf("expected echo payload %q, got %q", "ping", got)
	}
}

type failingHTTPStreamOpener struct{}

func (failingHTTPStreamOpener) OpenStream(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("stream unauthorized")
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
