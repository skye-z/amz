package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/skye-z/amz/internal/config"
)

const (
	// 表示连接管理器尚未建立会话。
	ConnStateIdle = "idle"
	// 表示连接管理器正在准备建立会话。
	ConnStateConnecting = "connecting"
	// 表示连接管理器已具备传输参数。
	ConnStateReady = "ready"
)

// 描述建立 QUIC 会话所需的最小参数。
type QUICOptions struct {
	Endpoint             string
	ServerName           string
	EnableDatagrams      bool
	Keepalive            string
	CongestionControl    string
	ConnectionParameters map[string]string
	ClientPrivateKey     string
	ClientCertificate    string
	PeerPublicKey        string
}

// 描述建立 HTTP/3 客户端连接所需的最小参数。
type HTTP3Options struct {
	Authority            string
	EnableDatagrams      bool
	ConnectionParameters map[string]string
}

// 描述连接管理器当前的最小状态快照。
type ConnectionSnapshot struct {
	State    string
	Endpoint string
	SNI      string
}

// 持有连接管理阶段的基础配置与状态。
type ConnectionManager struct {
	mu     sync.Mutex
	cfg    config.KernelConfig
	state  string
	quic   QUICOptions
	h3     HTTP3Options
	stats  connectionStats
	compat *CloudflareCompatLayer
	dialer transportDialer
	conn   quicErrorCloser
	h3conn h3ClientConn
}

type quicErrorCloser interface {
	CloseWithError(code uint64, msg string) error
}

type h3ClientConn interface {
	Close() error
	AwaitSettings(ctx context.Context, requireDatagrams, requireExtendedConnect bool) error
	Raw() *http3.ClientConn
	RequestConn() h3RequestStreamOpener
}

type h3RequestStreamOpener interface {
	OpenRequestStream(ctx context.Context) (h3RequestStream, error)
}

type h3RequestStream interface {
	SendRequestHeader(req *http.Request) error
	ReadResponse() (*http.Response, error)
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	CancelRead(quic.StreamErrorCode)
}

type http3RequestConnAdapter struct{ conn *http3.ClientConn }

func (a *http3RequestConnAdapter) OpenRequestStream(ctx context.Context) (h3RequestStream, error) {
	stream, err := a.conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	return &http3RequestStreamAdapter{stream: stream}, nil
}

type http3RequestStreamAdapter struct{ stream *http3.RequestStream }

func (a *http3RequestStreamAdapter) SendRequestHeader(req *http.Request) error {
	return a.stream.SendRequestHeader(req)
}

func (a *http3RequestStreamAdapter) ReadResponse() (*http.Response, error) {
	return a.stream.ReadResponse()
}

func (a *http3RequestStreamAdapter) Read(b []byte) (int, error) {
	return a.stream.Read(b)
}

func (a *http3RequestStreamAdapter) Write(b []byte) (int, error) {
	return a.stream.Write(b)
}

func (a *http3RequestStreamAdapter) Close() error {
	return a.stream.Close()
}

func (a *http3RequestStreamAdapter) SetDeadline(t time.Time) error {
	return a.stream.SetDeadline(t)
}

func (a *http3RequestStreamAdapter) SetReadDeadline(t time.Time) error {
	return a.stream.SetReadDeadline(t)
}

func (a *http3RequestStreamAdapter) SetWriteDeadline(t time.Time) error {
	return a.stream.SetWriteDeadline(t)
}

func (a *http3RequestStreamAdapter) LocalAddr() net.Addr { return nil }

func (a *http3RequestStreamAdapter) RemoteAddr() net.Addr { return nil }

func (a *http3RequestStreamAdapter) SendDatagram(b []byte) error {
	return a.stream.SendDatagram(b)
}

func (a *http3RequestStreamAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return a.stream.ReceiveDatagram(ctx)
}

func (a *http3RequestStreamAdapter) CancelRead(code quic.StreamErrorCode) {
	a.stream.CancelRead(code)
}

type transportDialer interface {
	Dial(ctx context.Context, quic QUICOptions, h3 HTTP3Options) (quicErrorCloser, h3ClientConn, time.Duration, error)
}

type realTransportDialer struct{}

func (d realTransportDialer) Dial(ctx context.Context, quicOpts QUICOptions, h3Opts HTTP3Options) (quicErrorCloser, h3ClientConn, time.Duration, error) {
	started := time.Now()

	addr, err := net.ResolveUDPAddr("udp", quicOpts.Endpoint)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("resolve udp endpoint: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("listen udp: %w", err)
	}
	conn, err := quic.Dial(ctx, udpConn, addr, buildTLSConfig(quicOpts), buildQUICConfig(quicOpts))
	if err != nil {
		udpConn.Close()
		return nil, nil, 0, fmt.Errorf("dial quic: %w", err)
	}
	transport := buildHTTP3Transport(quicOpts, h3Opts)
	clientConn := transport.NewClientConn(conn)
	return &quicConnAdapter{conn: conn}, &http3ClientConnAdapter{transport: transport, conn: clientConn}, time.Since(started), nil
}

func buildHTTP3Transport(quicOpts QUICOptions, h3Opts HTTP3Options) *http3.Transport {
	enableDatagrams := quicOpts.EnableDatagrams && h3Opts.EnableDatagrams
	transport := &http3.Transport{
		EnableDatagrams:    enableDatagrams,
		DisableCompression: true,
	}
	if enableDatagrams {
		transport.AdditionalSettings = map[uint64]uint64{
			0x276: 1,
		}
	}
	return transport
}

func buildTLSConfig(opts QUICOptions) *tls.Config {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	serverName := tlsServerNameForOptions(opts)
	cfg := &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"h3"},
		RootCAs:    rootCAs,
	}
	if requiresPinnedMASQUETrust(opts) {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = buildPinnedMASQUEVerifier(serverName, opts.PeerPublicKey)
	}
	if cert, err := buildClientCertificate(opts); err == nil && cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func tlsServerNameForOptions(opts QUICOptions) string {
	if requiresPinnedMASQUETrust(opts) {
		return "masque.cloudflareclient.com"
	}
	if strings.TrimSpace(opts.ServerName) != "" {
		return strings.TrimSpace(opts.ServerName)
	}
	return "warp.cloudflare.com"
}

func requiresPinnedMASQUETrust(opts QUICOptions) bool {
	if strings.TrimSpace(opts.PeerPublicKey) == "" {
		return false
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(opts.Endpoint))
	if err != nil {
		return false
	}
	return port != "443"
}

func buildPinnedMASQUEVerifier(serverName, pinnedPublicKey string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	normalizedPinned := normalizePEM(strings.TrimSpace(pinnedPublicKey))
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("missing peer certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("peer certificate is not currently valid")
		}
		if err := cert.VerifyHostname(serverName); err != nil {
			return fmt.Errorf("verify peer hostname: %w", err)
		}
		pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal peer public key: %w", err)
		}
		peerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
		if normalizePEM(string(peerPEM)) != normalizedPinned {
			return fmt.Errorf("peer public key does not match pinned key")
		}
		return nil
	}
}

func normalizePEM(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), "\n")
}

func buildQUICConfig(opts QUICOptions) *quic.Config {
	return &quic.Config{
		EnableDatagrams: opts.EnableDatagrams,
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 4 * time.Second,
	}
}

type quicConnAdapter struct{ conn *quic.Conn }

func (a *quicConnAdapter) CloseWithError(code uint64, msg string) error {
	return a.conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

type http3ClientConnAdapter struct {
	transport *http3.Transport
	conn      *http3.ClientConn
}

func (a *http3ClientConnAdapter) Close() error {
	if a.transport != nil {
		a.transport.Close()
	}
	return nil
}

func (a *http3ClientConnAdapter) AwaitSettings(ctx context.Context, requireDatagrams, requireExtendedConnect bool) error {
	return nil
}

func (a *http3ClientConnAdapter) Raw() *http3.ClientConn {
	return a.conn
}

func (a *http3ClientConnAdapter) RequestConn() h3RequestStreamOpener {
	if a.conn == nil {
		return nil
	}
	return &http3RequestConnAdapter{conn: a.conn}
}

// 发起一次最小真实 QUIC/H3 建链。
func (m *ConnectionManager) Connect(ctx context.Context) error {
	m.mu.Lock()
	if m.state == ConnStateReady {
		m.mu.Unlock()
		return nil
	}
	m.state = ConnStateConnecting
	dialer := m.dialer
	quicOpts := m.quic
	h3Opts := m.h3
	compat := m.compat
	m.mu.Unlock()

	if dialer == nil {
		dialer = realTransportDialer{}
	}
	conn, h3conn, latency, err := dialer.Dial(ctx, quicOpts, h3Opts)
	if err != nil {
		m.mu.Lock()
		m.state = ConnStateIdle
		m.mu.Unlock()
		return err
	}

	if err := h3conn.AwaitSettings(ctx, h3Opts.EnableDatagrams, true); err != nil {
		_ = h3conn.Close()
		_ = conn.CloseWithError(0, "settings failed")
		m.mu.Lock()
		m.state = ConnStateIdle
		m.mu.Unlock()
		if compat != nil {
			return compat.WrapProtocolError("http3-settings", err)
		}
		return err
	}

	m.mu.Lock()
	m.conn = conn
	m.h3conn = h3conn
	m.state = ConnStateReady
	m.mu.Unlock()
	m.RecordHandshakeLatency(latency)
	return nil
}

// 关闭当前连接句柄并回到空闲态。
func (m *ConnectionManager) Close() error {
	m.mu.Lock()
	conn := m.conn
	h3conn := m.h3conn
	m.conn = nil
	m.h3conn = nil
	m.state = ConnStateIdle
	m.mu.Unlock()

	if h3conn != nil {
		_ = h3conn.Close()
	}
	if conn != nil {
		return conn.CloseWithError(0, "closed")
	}
	return nil
}

// 返回当前已建立的 HTTP/3 client connection 适配器。
func (m *ConnectionManager) HTTP3Conn() h3ClientConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h3conn
}

// 将配置映射为最小 QUIC 连接参数。
func BuildQUICOptions(cfg config.KernelConfig) (QUICOptions, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return QUICOptions{}, err
	}
	return QUICOptions{
		Endpoint:             clone.Endpoint,
		ServerName:           clone.SNI,
		EnableDatagrams:      true,
		Keepalive:            clone.Keepalive.String(),
		CongestionControl:    clone.QUIC.CongestionControl,
		ConnectionParameters: cloneConnectionParameters(clone.QUIC.ConnectionParameters),
		ClientPrivateKey:     clone.TLS.ClientPrivateKey,
		ClientCertificate:    clone.TLS.ClientCertificate,
		PeerPublicKey:        clone.TLS.PeerPublicKey,
	}, nil
}

// 基于 QUIC 参数生成 HTTP/3 连接参数。
func BuildHTTP3Options(quic QUICOptions) HTTP3Options {
	return HTTP3Options{
		Authority:            quic.Endpoint,
		EnableDatagrams:      quic.EnableDatagrams,
		ConnectionParameters: cloneConnectionParameters(quic.ConnectionParameters),
	}
}

// 复制连接参数映射，避免不同阶段共享可变状态。
func cloneConnectionParameters(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func buildClientCertificate(opts QUICOptions) (*tls.Certificate, error) {
	if opts.ClientPrivateKey == "" || opts.ClientCertificate == "" {
		return nil, nil
	}
	priv, err := parseECDSAPrivateKey(opts.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(opts.ClientCertificate)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

func parseECDSAPrivateKey(encoded string) (*ecdsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(raw)
}

// 创建最小连接管理器骨架。
func NewConnectionManager(cfg config.KernelConfig) (*ConnectionManager, error) {
	quic, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	compat, err := NewCloudflareCompatLayer(cfg)
	if err != nil {
		return nil, fmt.Errorf("build cloudflare compat: %w", err)
	}
	return &ConnectionManager{
		cfg:    cfg,
		state:  ConnStateIdle,
		quic:   quic,
		h3:     BuildHTTP3Options(quic),
		compat: compat,
	}, nil
}

// 返回当前连接管理器状态快照。
func (m *ConnectionManager) Snapshot() ConnectionSnapshot {
	return ConnectionSnapshot{
		State:    m.state,
		Endpoint: m.quic.Endpoint,
		SNI:      m.quic.ServerName,
	}
}

// 记录最近一次连接握手时延。
func (m *ConnectionManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

// 累加连接阶段上行字节数。
func (m *ConnectionManager) AddTxBytes(n int) {
	m.stats.AddTxBytes(n)
}

// 累加连接阶段下行字节数。
func (m *ConnectionManager) AddRxBytes(n int) {
	m.stats.AddRxBytes(n)
}

// 返回连接阶段统计快照。
func (m *ConnectionManager) Stats() config.Stats {
	return m.stats.Snapshot()
}

var contextIDZero = quicvarint.Append(nil, 0)
