package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/testkit"
	internaltun "github.com/skye-z/amz/internal/tun"
	"github.com/yosida95/uritemplate/v3"
)

const (
	transportRuntimeConnectIPPath   = "/connect-ip"
	transportRuntimeIPv4ZeroAddr    = "0.0.0.0"
	transportRuntimeIPv4Broadcast   = "255.255.255.255"
	transportRuntimeMasqueLocalhost = testkit.LocalhostName
	transportRuntimeTargetEndpoint  = testkit.TestDomain + ":443"
)

type fakeQUICConn struct {
	closed bool
}

func (c *fakeQUICConn) CloseWithError(code uint64, msg string) error {
	c.closed = true
	return nil
}

type fakeH3Client struct {
	awaitErr error
}

func (c *fakeH3Client) Close() error { return nil }
func (c *fakeH3Client) AwaitSettings(ctx context.Context, requireDatagrams, requireExtendedConnect bool) error {
	return c.awaitErr
}
func (c *fakeH3Client) Raw() *http3.ClientConn     { return nil }
func (c *fakeH3Client) RequestConn() h3RequestConn { return nil }

type fakeTransportDialer struct {
	err      error
	called   bool
	lastQUIC QUICOptions
	lastH3   HTTP3Options
	conn     quicConn
	h3       h3ClientConn
	latency  time.Duration
}

func (d *fakeTransportDialer) Dial(ctx context.Context, quic QUICOptions, h3 HTTP3Options) (quicConn, h3ClientConn, time.Duration, error) {
	d.called = true
	d.lastQUIC = quic
	d.lastH3 = h3
	if d.err != nil {
		return nil, nil, 0, d.err
	}
	return d.conn, d.h3, d.latency, nil
}

type fakeConnectIPSession struct {
	closed bool
	info   SessionInfo
}

func (s *fakeConnectIPSession) Close() error {
	s.closed = true
	return nil
}

func (s *fakeConnectIPSession) SessionInfo() SessionInfo {
	return s.info
}

func (s *fakeConnectIPSession) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	default:
		return 0, context.Cause(ctx)
	}
}

func (s *fakeConnectIPSession) WritePacket(ctx context.Context, packet []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
		return nil, nil
	}
}

type fakeConnectIPDialer struct {
	err      error
	response *http.Response
	called   bool
	lastQUIC QUICOptions
	lastH3   HTTP3Options
	lastOpts ConnectIPOptions
	session  connectIPSession
	latency  time.Duration
}

func (d *fakeConnectIPDialer) Dial(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, *http.Response, time.Duration, error) {
	d.called = true
	d.lastQUIC = quic
	d.lastH3 = h3
	d.lastOpts = opts
	if d.err != nil {
		return nil, d.response, 0, d.err
	}
	return d.session, d.response, d.latency, nil
}

// 验证连接管理器会执行真实建链路径并更新状态与握手时延。
func TestConnectionManagerConnect(t *testing.T) {
	mgr, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	dialer := &fakeTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}, latency: 25 * time.Millisecond}
	mgr.dialer = dialer

	if err := mgr.Connect(context.Background()); err != nil {
		t.Fatalf("expected connect success, got %v", err)
	}
	if !dialer.called {
		t.Fatal("expected dialer to be called")
	}
	if mgr.Snapshot().State != ConnStateReady {
		t.Fatalf("expected ready state, got %q", mgr.Snapshot().State)
	}
	if mgr.Stats().HandshakeLatency != 25*time.Millisecond {
		t.Fatalf("expected latency 25ms, got %s", mgr.Stats().HandshakeLatency)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if mgr.Snapshot().State != ConnStateIdle {
		t.Fatalf("expected idle after close, got %q", mgr.Snapshot().State)
	}
}

// 验证连接管理器在建链失败时保留错误并回到空闲态。
func TestConnectionManagerConnectFailure(t *testing.T) {
	mgr, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	mgr.dialer = &fakeTransportDialer{err: errors.New("dial failed")}

	err = mgr.Connect(context.Background())
	if err == nil {
		t.Fatal("expected connect error")
	}
	if mgr.Snapshot().State != ConnStateIdle {
		t.Fatalf("expected idle state after failure, got %q", mgr.Snapshot().State)
	}
}

// 验证 H3 SETTINGS 缺少 Cloudflare 依赖能力时会返回兼容层错误上下文。
func TestConnectionManagerConnectWrapsCloudflareSettingsError(t *testing.T) {
	mgr, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	mgr.dialer = &fakeTransportDialer{
		conn:    &fakeQUICConn{},
		h3:      &fakeH3Client{awaitErr: errors.New("http3 settings: datagrams not enabled")},
		latency: 5 * time.Millisecond,
	}

	err = mgr.Connect(context.Background())
	if err == nil {
		t.Fatal("expected connect error")
	}
	if !errors.Is(err, internalcloudflare.ErrCompat) {
		t.Fatalf("expected cloudflare compat error, got %v", err)
	}
	var compatErr *internalcloudflare.CompatError
	if !errors.As(err, &compatErr) {
		t.Fatal("expected contextual cloudflare compat error")
	}
	if compatErr.Quirk != CloudflareQuirkMissingDatagrams {
		t.Fatalf("expected quirk %q, got %q", CloudflareQuirkMissingDatagrams, compatErr.Quirk)
	}
}

// 验证 CONNECT-IP 会话管理器会通过真实会话建立路径更新地址与路由。
func TestConnectIPSessionManagerOpen(t *testing.T) {
	mgr, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	dialer := &fakeConnectIPDialer{latency: 15 * time.Millisecond, session: &fakeConnectIPSession{info: SessionInfo{
		IPv4:   testkit.TunIPv4CIDR,
		IPv6:   testkit.TunIPv6AltCIDR,
		Routes: []string{testkit.DefaultRouteV4, testkit.DefaultRouteV6},
	}}}
	mgr.dialer = dialer

	if err := mgr.Open(context.Background()); err != nil {
		t.Fatalf("expected open success, got %v", err)
	}
	if !dialer.called {
		t.Fatal("expected connect-ip dialer to be called")
	}
	snapshot := mgr.Snapshot()
	if snapshot.State != SessionStateReady {
		t.Fatalf("expected ready state, got %q", snapshot.State)
	}
	if mgr.PacketEndpoint() == nil {
		t.Fatal("expected packet endpoint after session open")
	}
	if snapshot.IPv4 != testkit.TunIPv4CIDR {
		t.Fatalf("expected ipv4 session info, got %q", snapshot.IPv4)
	}
	if len(snapshot.Routes) != 2 {
		t.Fatalf("expected routes in snapshot, got %+v", snapshot.Routes)
	}
	if mgr.Stats().HandshakeLatency != 15*time.Millisecond {
		t.Fatalf("expected session latency 15ms, got %s", mgr.Stats().HandshakeLatency)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("expected session close success, got %v", err)
	}
	if mgr.Snapshot().State != SessionStateIdle {
		t.Fatalf("expected idle state after close, got %q", mgr.Snapshot().State)
	}
}

// 验证 CONNECT-IP 会话阶段会将真实 HTTP 状态码映射为 Cloudflare 特殊响应错误。
func TestConnectIPSessionManagerOpenWrapsCloudflareResponse(t *testing.T) {
	mgr, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	mgr.dialer = &fakeConnectIPDialer{
		err:      errors.New("connect-ip: server responded with 429"),
		response: &http.Response{StatusCode: http.StatusTooManyRequests},
	}

	err = mgr.Open(context.Background())
	if err == nil {
		t.Fatal("expected connect-ip open error")
	}
	if !errors.Is(err, internalcloudflare.ErrCompat) {
		t.Fatalf("expected cloudflare compat error, got %v", err)
	}
	var compatErr *internalcloudflare.CompatError
	if !errors.As(err, &compatErr) {
		t.Fatal("expected contextual cloudflare compat error")
	}
	if compatErr.Quirk != CloudflareQuirkRateLimited {
		t.Fatalf("expected quirk %q, got %q", CloudflareQuirkRateLimited, compatErr.Quirk)
	}
}

// 验证核心 bootstrap 会把已建立的 HTTP/3 连接绑定进 stream manager 并置为就绪态。
func TestCoreTunnelDialerBindsHTTP3ConnIntoStreamManager(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	}

	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	fakeH3 := &fakeH3Client{}
	connectionManager.dialer = &fakeTransportDialer{conn: &fakeQUICConn{}, h3: fakeH3, latency: 5 * time.Millisecond}

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected connect-ip session manager creation success, got %v", err)
	}
	sessionManager.dialer = &fakeConnectIPDialer{session: &fakeConnectIPSession{info: SessionInfo{IPv4: testkit.TunIPv4CIDR}}}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, &stubHTTPStreamDialer{conn: clientConn})
	if err != nil {
		t.Fatalf("expected core tunnel dialer creation success, got %v", err)
	}
	dialer.provider = &fakePlatformProvider{platform: "linux", delegate: internaltun.NewFakeProvider()}
	dialer.adapter = internaltun.NewFakeAdapter()
	dialer.packetRelay = func(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
		<-ctx.Done()
		return context.Cause(ctx)
	}
	defer func() { _ = dialer.Close() }()

	if _, err := dialer.DialContext(context.Background(), "tcp", transportRuntimeTargetEndpoint); err != nil {
		t.Fatalf("expected downstream dial success, got %v", err)
	}

	streamManager := dialer.StreamManager()
	if streamManager == nil {
		t.Fatal("expected core tunnel dialer to expose a bound stream manager")
	}
	if streamManager.h3conn != h3ClientConn(fakeH3) {
		t.Fatal("expected stream manager to reuse established http3 connection")
	}
	if snapshot := streamManager.Snapshot(); snapshot.State != StreamStateReady {
		t.Fatalf("expected ready stream manager, got %+v", snapshot)
	}
	if sessionManager.h3conn != h3ClientConn(fakeH3) {
		t.Fatal("expected connect-ip session manager to reuse established http3 connection")
	}
}

// 验证保活管理器会执行有限重试直到成功。
func TestKeepaliveManagerReconnect(t *testing.T) {
	mgr := NewKeepaliveManager(RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond})
	attempts := 0
	err := mgr.Reconnect(context.Background(), "timeout", func(ctx context.Context, attempt int) error {
		attempts = attempt
		if attempt < 3 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected reconnect success, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if len(mgr.Events()) == 0 {
		t.Fatal("expected reconnect events")
	}
	last := mgr.Events()[len(mgr.Events())-1]
	if last.State != ConnStateReady {
		t.Fatalf("expected final ready event, got %q", last.State)
	}
}

// 验证真实 QUIC/H3/connect-ip 会话协商后会更新地址与路由。
func TestConnectIPSessionManagerOpenIntegration(t *testing.T) {
	tlsConfig, certPool := newTestTLSConfig(t)
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(testkit.LocalhostIPv4).To4(), Port: 0})
	if err != nil {
		t.Fatalf("expected udp listen success, got %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })

	template := fmt.Sprintf("https://%s:%d%s", transportRuntimeMasqueLocalhost, udpConn.LocalAddr().(*net.UDPAddr).Port, transportRuntimeConnectIPPath)
	proxy := &connectip.Proxy{}
	connCh := make(chan *connectip.Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(transportRuntimeConnectIPPath, func(w http.ResponseWriter, r *http.Request) {
		tpl := uritemplate.MustNew(template)
		parsed, err := connectip.ParseRequest(r, tpl)
		if err != nil {
			t.Errorf("expected parse request success, got %v", err)
			return
		}
		conn, err := proxy.Proxy(w, parsed)
		if err != nil {
			t.Errorf("expected proxy success, got %v", err)
			return
		}
		connCh <- conn
	})
	server := http3.Server{Handler: mux, EnableDatagrams: true, TLSConfig: tlsConfig}
	go func() { _ = server.Serve(udpConn) }()
	t.Cleanup(func() { _ = server.Close() })

	endpoint := net.JoinHostPort(transportRuntimeMasqueLocalhost, fmt.Sprintf("%d", udpConn.LocalAddr().(*net.UDPAddr).Port))
	manager, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       endpoint,
		SNI:            transportRuntimeMasqueLocalhost,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.dialer = realTransportDialerWithTLS{tlsConfig: &tls.Config{ServerName: transportRuntimeMasqueLocalhost, RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatalf("expected connection success, got %v", err)
	}

	sessionManager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       endpoint,
		SNI:            transportRuntimeMasqueLocalhost,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf("expected session manager creation success, got %v", err)
	}
	sessionManager.BindHTTP3Conn(manager.HTTP3Conn())
	go func() {
		conn := <-connCh
		_ = conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix(testkit.TunIPv4CIDR), netip.MustParsePrefix(testkit.TunIPv6AltCIDR)})
		_ = conn.AdvertiseRoute(ctx, []connectip.IPRoute{{StartIP: netip.MustParseAddr(transportRuntimeIPv4ZeroAddr), EndIP: netip.MustParseAddr(transportRuntimeIPv4Broadcast)}})
	}()
	if err := sessionManager.Open(ctx); err != nil {
		t.Fatalf("expected connect-ip open success, got %v", err)
	}
	snapshot := sessionManager.Snapshot()
	if snapshot.State != SessionStateReady {
		t.Fatalf("expected ready state, got %q", snapshot.State)
	}
	if snapshot.IPv4 != testkit.TunIPv4CIDR {
		t.Fatalf("expected ipv4 assignment, got %q", snapshot.IPv4)
	}
	if snapshot.IPv6 != testkit.TunIPv6AltCIDR {
		t.Fatalf("expected ipv6 assignment, got %q", snapshot.IPv6)
	}
	if len(snapshot.Routes) != 1 {
		t.Fatalf("expected one route, got %+v", snapshot.Routes)
	}
}

// 验证真实 H3 transport 会携带 Cloudflare 当前链路要求的兼容 settings。
func TestBuildHTTP3TransportUsesCloudflareCompatSettings(t *testing.T) {
	transport := buildHTTP3Transport(
		QUICOptions{EnableDatagrams: true},
		HTTP3Options{EnableDatagrams: true},
	)

	if transport == nil {
		t.Fatal("expected transport")
	}
	if !transport.EnableDatagrams {
		t.Fatal("expected datagrams enabled")
	}
	if !transport.DisableCompression {
		t.Fatal("expected compression disabled")
	}
	if got := transport.AdditionalSettings[0x276]; got != 1 {
		t.Fatalf("expected deprecated H3 datagram setting 0x276=1, got %d", got)
	}
}

type realTransportDialerWithTLS struct{ tlsConfig *tls.Config }

func (d realTransportDialerWithTLS) Dial(ctx context.Context, quicOpts QUICOptions, h3Opts HTTP3Options) (quicConn, h3ClientConn, time.Duration, error) {
	started := time.Now()
	addr, err := net.ResolveUDPAddr("udp", quicOpts.Endpoint)
	if err != nil {
		return nil, nil, 0, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, 0, err
	}
	conn, err := quic.Dial(ctx, udpConn, addr, d.tlsConfig, &quic.Config{EnableDatagrams: h3Opts.EnableDatagrams})
	if err != nil {
		return nil, nil, 0, err
	}
	tr := &http3.Transport{EnableDatagrams: h3Opts.EnableDatagrams}
	cc := tr.NewClientConn(conn)
	return &quicConnAdapter{conn: conn}, &http3ClientConnAdapter{transport: tr, conn: cc}, time.Since(started), nil
}

func newTestTLSConfig(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key generation success, got %v", err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: transportRuntimeMasqueLocalhost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{transportRuntimeMasqueLocalhost}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("expected certificate creation success, got %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	pool := x509.NewCertPool()
	pool.AddCert(tpl)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("expected parse cert success, got %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}}, pool
}
