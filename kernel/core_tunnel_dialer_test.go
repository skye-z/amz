package kernel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
)

type countingTransportDialer struct {
	calls int
	conn  quicConn
	h3    h3ClientConn
	err   error
}

func (d *countingTransportDialer) Dial(ctx context.Context, quic QUICOptions, h3 HTTP3Options) (quicConn, h3ClientConn, time.Duration, error) {
	d.calls++
	if d.err != nil {
		return nil, nil, 0, d.err
	}
	return d.conn, d.h3, time.Millisecond, nil
}

type countingConnectIPDialer struct {
	calls   int
	session connectIPSession
	err     error
}

func (d *countingConnectIPDialer) Dial(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, *http.Response, time.Duration, error) {
	d.calls++
	if d.err != nil {
		return nil, nil, 0, d.err
	}
	return d.session, nil, time.Millisecond, nil
}

type stubHTTPStreamDialer struct {
	calls int
	conn  net.Conn
	err   error
}

func (d *stubHTTPStreamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

// 验证核心 dialer 会在真实拨号前建立并复用 QUIC/H3 与 CONNECT-IP 会话。
func TestCoreTunnelDialerEnsuresCoreSessionOnce(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	}

	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	transportDialer := &countingTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}}
	connectionManager.dialer = transportDialer

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager creation success, got %v", err)
	}
	connectDialer := &countingConnectIPDialer{session: &fakeConnectIPSession{}}
	sessionManager.dialer = connectDialer

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	streamDialer := &stubHTTPStreamDialer{conn: clientConn}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf("expected core tunnel dialer creation success, got %v", err)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}

	if transportDialer.calls != 1 {
		t.Fatalf("expected one transport dial, got %d", transportDialer.calls)
	}
	if connectDialer.calls != 1 {
		t.Fatalf("expected one connect-ip dial, got %d", connectDialer.calls)
	}
	if streamDialer.calls != 1 {
		t.Fatalf("expected one downstream dial, got %d", streamDialer.calls)
	}

	if _, err := dialer.DialContext(context.Background(), "tcp", "example.com:443"); err != nil {
		t.Fatalf("expected second dial success, got %v", err)
	}
	if transportDialer.calls != 1 {
		t.Fatalf("expected transport session reuse, got %d calls", transportDialer.calls)
	}
	if connectDialer.calls != 1 {
		t.Fatalf("expected connect-ip session reuse, got %d calls", connectDialer.calls)
	}
	if streamDialer.calls != 2 {
		t.Fatalf("expected underlying stream dialer to be called twice, got %d", streamDialer.calls)
	}
}

// 验证核心 dialer 会将建链错误透传给上层。
func TestCoreTunnelDialerPropagatesBootstrapError(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: "127.0.0.1:0"},
	}

	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	transportDialer := &countingTransportDialer{err: errors.New("quic unavailable")}
	connectionManager.dialer = transportDialer

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager creation success, got %v", err)
	}
	streamDialer := &stubHTTPStreamDialer{}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf("expected core tunnel dialer creation success, got %v", err)
	}

	_, err = dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected bootstrap error")
	}
	if transportDialer.calls != 1 {
		t.Fatalf("expected one bootstrap attempt, got %d", transportDialer.calls)
	}
	if streamDialer.calls != 0 {
		t.Fatalf("expected underlying dialer not to be called, got %d", streamDialer.calls)
	}
}
