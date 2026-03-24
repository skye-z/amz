package kernel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	internaltun "github.com/skye-z/amz/internal/tun"
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

type fakePacketSession struct{}

func (s *fakePacketSession) Close() error { return nil }
func (s *fakePacketSession) SessionInfo() SessionInfo {
	return SessionInfo{
		IPv4: "172.16.0.2/32",
		IPv6: "2606:4700:110:8d36::2/128",
	}
}
func (s *fakePacketSession) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	<-ctx.Done()
	return 0, context.Cause(ctx)
}
func (s *fakePacketSession) WritePacket(ctx context.Context, packet []byte) ([]byte, error) {
	return nil, nil
}

type fakePlatformProvider struct {
	platform string
	delegate *internaltun.FakeProvider
}

func (p *fakePlatformProvider) Platform() string { return p.platform }
func (p *fakePlatformProvider) IsFake() bool     { return true }
func (p *fakePlatformProvider) PlaceholderError() error {
	return &internaltun.PlaceholderError{Platform: p.platform, Component: "provider"}
}
func (p *fakePlatformProvider) Open(ctx context.Context, cfg internaltun.DeviceConfig) (internaltun.Device, error) {
	return p.delegate.Open(ctx, cfg)
}
func (p *fakePlatformProvider) Close() error { return p.delegate.Close() }

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
	connectDialer := &countingConnectIPDialer{session: &fakePacketSession{}}
	sessionManager.dialer = connectDialer

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	streamDialer := &stubHTTPStreamDialer{conn: clientConn}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf("expected core tunnel dialer creation success, got %v", err)
	}
	dialer.provider = &fakePlatformProvider{platform: "linux", delegate: internaltun.NewFakeProvider()}
	dialer.adapter = internaltun.NewFakeAdapter()
	relayCalls := 0
	dialer.packetRelay = func(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
		relayCalls++
		<-ctx.Done()
		return context.Cause(ctx)
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
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && relayCalls == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if relayCalls != 1 {
		t.Fatalf("expected relay to start once, got %d", relayCalls)
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
	if err := dialer.Close(); err != nil {
		t.Fatalf("expected core dialer close success, got %v", err)
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
	dialer.provider = &fakePlatformProvider{platform: "linux", delegate: internaltun.NewFakeProvider()}
	dialer.adapter = internaltun.NewFakeAdapter()

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

func TestHTTPProxyManagerSetCoreTunnelDialerBindsStreamManager(t *testing.T) {
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
	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager creation success, got %v", err)
	}
	manager, err := NewHTTPProxyManager(cfg)
	if err != nil {
		t.Fatalf("expected http proxy manager creation success, got %v", err)
	}

	if err := manager.SetCoreTunnelDialer(connectionManager, sessionManager, &stubHTTPStreamDialer{}); err != nil {
		t.Fatalf("expected core tunnel dialer binding success, got %v", err)
	}
	if manager.currentHTTPDialer() == nil {
		t.Fatal("expected core tunnel dialer to be installed as HTTP dialer")
	}
	if manager.currentStreamManager() == nil {
		t.Fatal("expected stream manager to be bound with core tunnel dialer")
	}
}
