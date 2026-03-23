package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
)

type fakeQUICConn struct {
	closed bool
}

func (c *fakeQUICConn) CloseWithError(code uint64, msg string) error {
	c.closed = true
	return nil
}

type fakeH3Client struct{}

func (c *fakeH3Client) Close() error { return nil }

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

type fakeConnectIPDialer struct {
	err      error
	called   bool
	lastQUIC QUICOptions
	lastH3   HTTP3Options
	lastOpts ConnectIPOptions
	session  connectIPSession
	latency  time.Duration
}

func (d *fakeConnectIPDialer) Dial(ctx context.Context, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, time.Duration, error) {
	d.called = true
	d.lastQUIC = quic
	d.lastH3 = h3
	d.lastOpts = opts
	if d.err != nil {
		return nil, 0, d.err
	}
	return d.session, d.latency, nil
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
		IPv4:   "172.16.0.2/32",
		IPv6:   "2606:4700:110:8765::2/128",
		Routes: []string{"0.0.0.0/0", "::/0"},
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
	if snapshot.IPv4 != "172.16.0.2/32" {
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
