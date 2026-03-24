package runtime_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/skye-z/amz/config"
	internalruntime "github.com/skye-z/amz/internal/runtime"
	httpproxy "github.com/skye-z/amz/proxy/http"
	socks5proxy "github.com/skye-z/amz/proxy/socks5"
	amztun "github.com/skye-z/amz/tun"
	"github.com/skye-z/amz/types"
)

func TestClientRuntimeMuxesHTTPAndSOCKS5OnSinglePort(t *testing.T) {
	t.Parallel()

	httpManager, err := httpproxy.NewManager(config.KernelConfig{
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
	httpManager.SetHTTPRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("http-ok")),
		}, nil
	}))

	socksManager, err := socks5proxy.NewManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected socks manager creation success, got %v", err)
	}
	socksManager.SetStreamManager(echoStreamOpener{})

	runtime, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{
		ListenAddress: "127.0.0.1:0",
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
	if listenAddress == "" || listenAddress == "127.0.0.1:0" {
		t.Fatalf("expected resolved listen address, got %q", listenAddress)
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/resource", nil)
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
	connectRequest := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}, []byte("example.com")...)
	connectRequest = append(connectRequest, 0x00, 0x50)
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
	if _, err := socksConn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected socks payload write success, got %v", err)
	}
	echoReply := make([]byte, 4)
	if _, err := io.ReadFull(socksConn, echoReply); err != nil {
		t.Fatalf("expected socks payload echo success, got %v", err)
	}
	if string(echoReply) != "ping" {
		t.Fatalf("expected echo payload %q, got %q", "ping", string(echoReply))
	}
}

func TestClientRuntimeStartsTUNInParallel(t *testing.T) {
	t.Parallel()

	httpManager, err := httpproxy.NewManager(config.KernelConfig{
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

	tunnel, err := amztun.NewRuntime(&config.KernelConfig{
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
		ListenAddress: "127.0.0.1:0",
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
	if tunnel.State() != types.StateRunning {
		t.Fatalf("expected tun runtime running, got %q", tunnel.State())
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("expected runtime close success, got %v", err)
	}
	if tunnel.State() != types.StateStopped {
		t.Fatalf("expected tun runtime stopped, got %q", tunnel.State())
	}
}

func TestNewClientRuntimeRejectsEmptyConfig(t *testing.T) {
	t.Parallel()

	_, err := internalruntime.NewClientRuntime(internalruntime.ClientRuntimeOptions{})
	if err == nil {
		t.Fatal("expected configuration error when no runtime is configured")
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
