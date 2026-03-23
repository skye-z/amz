package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
	"github.com/yosida95/uritemplate/v3"
)

const (
	// 表示 CONNECT-IP 扩展协议标识。
	ProtocolConnectIP = "connect-ip"
	// 表示会话管理器尚未建立 CONNECT-IP 会话。
	SessionStateIdle = "idle"
	// 表示会话管理器已完成最小会话协商。
	SessionStateReady = "ready"
)

// 描述建立 CONNECT-IP 会话所需的最小参数。
type ConnectIPOptions struct {
	Authority       string
	Protocol        string
	EnableDatagrams bool
}

// 描述 CONNECT-IP 会话管理器的最小状态快照。
type ConnectIPSnapshot struct {
	State    string
	Protocol string
	Endpoint string
	IPv4     string
	IPv6     string
	Routes   []string
}

// 描述会话建立后分配的地址与路由信息。
type SessionInfo struct {
	IPv4   string
	IPv6   string
	Routes []string
}

// 管理 CONNECT-IP 会话建立阶段的最小状态。
type ConnectIPSessionManager struct {
	mu      sync.Mutex
	state   string
	options ConnectIPOptions
	quic    QUICOptions
	h3      HTTP3Options
	h3conn  h3ClientConn
	info    SessionInfo
	stats   connectionStats
	dialer  connectIPDialer
	session connectIPSession
}

type connectIPSession interface {
	Close() error
	SessionInfo() SessionInfo
}

type connectIPDialer interface {
	Dial(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, time.Duration, error)
}

type realConnectIPSession struct {
	conn *connectip.Conn
	info SessionInfo
}

func (s *realConnectIPSession) Close() error             { return s.conn.Close() }
func (s *realConnectIPSession) SessionInfo() SessionInfo { return s.info }

type realConnectIPDialer struct{}

func (d realConnectIPDialer) Dial(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, time.Duration, error) {
	if h3conn == nil || h3conn.Raw() == nil {
		return nil, 0, fmt.Errorf("http3 client connection is required")
	}
	tmpl := uritemplate.MustNew("https://" + opts.Authority + "/connect-ip")
	started := time.Now()
	conn, _, err := connectip.Dial(ctx, h3conn.Raw(), tmpl)
	if err != nil {
		return nil, 0, err
	}
	prefixes, err := conn.LocalPrefixes(ctx)
	if err != nil {
		return nil, 0, err
	}
	routes, err := conn.Routes(ctx)
	if err != nil {
		return nil, 0, err
	}
	info := SessionInfo{Routes: make([]string, 0, len(routes))}
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() && info.IPv4 == "" {
			info.IPv4 = prefix.String()
		}
		if prefix.Addr().Is6() && info.IPv6 == "" {
			info.IPv6 = prefix.String()
		}
	}
	for _, route := range routes {
		info.Routes = append(info.Routes, route.StartIP.String()+"-"+route.EndIP.String())
	}
	return &realConnectIPSession{conn: conn, info: info}, time.Since(started), nil
}

// 基于 HTTP/3 参数生成 CONNECT-IP 会话参数。
func BuildConnectIPOptions(h3 HTTP3Options) ConnectIPOptions {
	return ConnectIPOptions{
		Authority:       h3.Authority,
		Protocol:        ProtocolConnectIP,
		EnableDatagrams: h3.EnableDatagrams,
	}
}

// 创建 CONNECT-IP 会话管理器骨架。
func NewConnectIPSessionManager(cfg config.KernelConfig) (*ConnectIPSessionManager, error) {
	quic, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	h3 := BuildHTTP3Options(quic)
	return &ConnectIPSessionManager{
		state:   SessionStateIdle,
		options: BuildConnectIPOptions(h3),
		quic:    quic,
		h3:      h3,
		dialer:  realConnectIPDialer{},
	}, nil
}

// 返回 CONNECT-IP 会话管理器的状态快照。
func (m *ConnectIPSessionManager) Snapshot() ConnectIPSnapshot {
	return ConnectIPSnapshot{
		State:    m.state,
		Protocol: m.options.Protocol,
		Endpoint: m.quic.Endpoint,
		IPv4:     m.info.IPv4,
		IPv6:     m.info.IPv6,
		Routes:   append([]string(nil), m.info.Routes...),
	}
}

// 更新 CONNECT-IP 会话分配的地址与路由。
func (m *ConnectIPSessionManager) UpdateSessionInfo(info SessionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.info = SessionInfo{
		IPv4:   info.IPv4,
		IPv6:   info.IPv6,
		Routes: append([]string(nil), info.Routes...),
	}
}

// 记录最近一次会话握手时延。
func (m *ConnectIPSessionManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

// 累加会话阶段上行字节数。
func (m *ConnectIPSessionManager) AddTxBytes(n int) {
	m.stats.AddTxBytes(n)
}

// 累加会话阶段下行字节数。
func (m *ConnectIPSessionManager) AddRxBytes(n int) {
	m.stats.AddRxBytes(n)
}

// 返回会话阶段统计快照。
func (m *ConnectIPSessionManager) Stats() types.Stats {
	return m.stats.Snapshot()
}

// 通过最小 dialer 完成一次 CONNECT-IP 会话建立。
func (m *ConnectIPSessionManager) Open(ctx context.Context) error {
	m.mu.Lock()
	dialer := m.dialer
	h3conn := m.h3conn
	quicOpts := m.quic
	h3Opts := m.h3
	opts := m.options
	m.mu.Unlock()
	if dialer == nil {
		return fmt.Errorf("connect-ip dialer is required")
	}
	session, latency, err := dialer.Dial(ctx, h3conn, quicOpts, h3Opts, opts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.session = session
	m.state = SessionStateReady
	m.info = session.SessionInfo()
	m.mu.Unlock()
	m.RecordHandshakeLatency(latency)
	return nil
}

// BindHTTP3Conn 绑定已建立的 HTTP/3 client connection，供会话阶段复用。
func (m *ConnectIPSessionManager) BindHTTP3Conn(conn h3ClientConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h3conn = conn
}

// 关闭当前 CONNECT-IP 会话并回到空闲态。
func (m *ConnectIPSessionManager) Close() error {
	m.mu.Lock()
	session := m.session
	m.session = nil
	m.state = SessionStateIdle
	m.info = SessionInfo{}
	m.mu.Unlock()
	if session != nil {
		return session.Close()
	}
	return nil
}
