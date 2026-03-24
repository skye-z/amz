package kernel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

const (
	ProtocolConnectStream = "connect-stream"
	StreamStateIdle       = "idle"
	StreamStateReady      = "ready"
)

type ConnectStreamOptions struct {
	Authority  string
	TargetHost string
	TargetPort string
	Protocol   string
}

type ConnectStreamSnapshot struct {
	State       string
	Protocol    string
	Endpoint    string
	RemoteAddr  string
	ConnectedAt time.Time
}

type StreamInfo struct {
	RemoteAddr string
	Protocol   string
}

type ConnectStreamManager struct {
	mu      sync.Mutex
	state   string
	options ConnectStreamOptions
	quic    QUICOptions
	h3      HTTP3Options
	h3conn  h3ClientConn
	stats   connectionStats
	compat  *CloudflareCompatLayer
	dialer  streamDialer
	streams map[string]*activeStream
}

type activeStream struct {
	conn     net.Conn
	info     StreamInfo
	local    string
	remote   string
	deadline time.Time
}

type managedStreamConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *managedStreamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type streamDialer interface {
	DialStream(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error)
}

type realStreamDialer struct{}

func (d realStreamDialer) DialStream(ctx context.Context, h3conn h3ClientConn, quicOpts QUICOptions, h3Opts HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
	if h3conn == nil || h3conn.RequestConn() == nil {
		return nil, nil, 0, fmt.Errorf("http3 client connection is required")
	}

	if ctx.Err() != nil {
		return nil, nil, 0, fmt.Errorf("context already canceled: %w", ctx.Err())
	}

	started := time.Now()
	clientConn := h3conn.RequestConn()

	targetAddr := opts.TargetHost
	if opts.TargetPort != "" {
		targetAddr = net.JoinHostPort(opts.TargetHost, opts.TargetPort)
	}

	rstr, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open request stream: %w", err)
	}

	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Scheme: "https", Host: targetAddr},
		Header:     make(http.Header),
		Host:       targetAddr,
		Proto:      "HTTP/3",
		ProtoMajor: 3,
	}
	req.Header.Set("X-Masque-Protocol", opts.Protocol)

	if err := rstr.SendRequestHeader(req); err != nil {
		_ = rstr.Close()
		return nil, nil, 0, fmt.Errorf("send request header: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		_ = rstr.Close()
		return nil, nil, 0, fmt.Errorf("read response: %w", err)
	}

	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(rsp.Body, 1024))
		rsp.Body.Close()
		_ = rstr.Close()
		return nil, rsp, 0, fmt.Errorf("connect failed: status=%d body=%s", rsp.StatusCode, string(body))
	}

	streamConn := &http3StreamConn{
		rsp:    rsp,
		stream: rstr,
		local:  quicOpts.Endpoint,
		remote: targetAddr,
	}

	return streamConn, rsp, time.Since(started), nil
}

type http3StreamConn struct {
	rsp     *http.Response
	stream  h3RequestStream
	local   string
	remote  string
	readBuf []byte
}

func (c *http3StreamConn) Read(b []byte) (int, error) {
	if c.stream == nil {
		return 0, io.EOF
	}
	return c.stream.Read(b)
}

func (c *http3StreamConn) Write(b []byte) (int, error) {
	if c.stream == nil {
		return 0, io.EOF
	}
	return c.stream.Write(b)
}

func (c *http3StreamConn) Close() error {
	if c.stream == nil {
		return nil
	}
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	if c.stream != nil {
		if addr := c.stream.LocalAddr(); addr != nil {
			return addr
		}
	}
	if c.local != "" {
		return staticAddr(c.local)
	}
	return staticAddr("0.0.0.0:0")
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		if addr := c.stream.RemoteAddr(); addr != nil {
			return addr
		}
	}
	if c.remote != "" {
		return staticAddr(c.remote)
	}
	return staticAddr("0.0.0.0:0")
}
func (c *http3StreamConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}
func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}
func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }

func BuildConnectStreamOptions(h3 HTTP3Options, targetHost, targetPort string) ConnectStreamOptions {
	return ConnectStreamOptions{
		Authority:  h3.Authority,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   ProtocolConnectStream,
	}
}

func NewConnectStreamManager(cfg config.KernelConfig) (*ConnectStreamManager, error) {
	quic, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	h3 := BuildHTTP3Options(quic)
	compat, err := NewCloudflareCompatLayer(cfg)
	if err != nil {
		return nil, fmt.Errorf("build cloudflare compat: %w", err)
	}
	return &ConnectStreamManager{
		state:   StreamStateIdle,
		options: compat.ApplyConnectStreamOptions(BuildConnectStreamOptions(h3, "", "")),
		quic:    quic,
		h3:      h3,
		compat:  compat,
		dialer:  realStreamDialer{},
		streams: make(map[string]*activeStream),
	}, nil
}

func (m *ConnectStreamManager) Snapshot() ConnectStreamSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ConnectStreamSnapshot{
		State:    m.state,
		Protocol: m.options.Protocol,
		Endpoint: m.quic.Endpoint,
	}
}

func (m *ConnectStreamManager) UpdateStreamInfo(id string, info StreamInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streams[id] != nil {
		m.streams[id].info = info
	}
}

func (m *ConnectStreamManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

func (m *ConnectStreamManager) AddTxBytes(n int) {
	m.stats.AddTxBytes(n)
}

func (m *ConnectStreamManager) AddRxBytes(n int) {
	m.stats.AddRxBytes(n)
}

func (m *ConnectStreamManager) Stats() types.Stats {
	return m.stats.Snapshot()
}

func (m *ConnectStreamManager) OpenStream(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	m.mu.Lock()
	if m.state != StreamStateReady {
		m.mu.Unlock()
		return nil, fmt.Errorf("connect stream manager not ready")
	}
	dialer := m.dialer
	h3conn := m.h3conn
	quicOpts := m.quic
	h3Opts := m.h3
	m.mu.Unlock()

	if dialer == nil {
		return nil, fmt.Errorf("stream dialer is required")
	}

	opts := BuildConnectStreamOptions(h3Opts, targetHost, targetPort)
	conn, rsp, latency, err := dialer.DialStream(ctx, h3conn, quicOpts, h3Opts, opts)
	if err != nil {
		if m.compat != nil {
			return nil, m.compat.WrapConnectStreamError("connect-stream", rsp, err)
		}
		return nil, err
	}

	m.RecordHandshakeLatency(latency)

	streamID := fmt.Sprintf("%s:%s", targetHost, targetPort)
	managedConn := &managedStreamConn{
		Conn: conn,
		onClose: func() {
			m.removeStream(streamID)
		},
	}
	m.mu.Lock()
	m.streams[streamID] = &activeStream{
		conn:   managedConn,
		info:   StreamInfo{RemoteAddr: net.JoinHostPort(targetHost, targetPort), Protocol: ProtocolConnectStream},
		local:  quicOpts.Endpoint,
		remote: net.JoinHostPort(targetHost, targetPort),
	}
	m.mu.Unlock()

	return managedConn, nil
}

func (m *ConnectStreamManager) removeStream(streamID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, streamID)
}

func (m *ConnectStreamManager) BindHTTP3Conn(conn h3ClientConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h3conn = conn
}

func (m *ConnectStreamManager) SetReady() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StreamStateReady
}

func (m *ConnectStreamManager) StreamEndpoint(targetHost, targetPort string) StreamRelayEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	streamID := fmt.Sprintf("%s:%s", targetHost, targetPort)
	stream := m.streams[streamID]
	if stream == nil {
		return nil
	}
	return stream
}

func (m *ConnectStreamManager) CloseStream(targetHost, targetPort string) error {
	m.mu.Lock()
	streamID := fmt.Sprintf("%s:%s", targetHost, targetPort)
	stream := m.streams[streamID]
	delete(m.streams, streamID)
	m.mu.Unlock()

	if stream != nil && stream.conn != nil {
		return stream.conn.Close()
	}
	return nil
}

func (m *ConnectStreamManager) Close() error {
	m.mu.Lock()
	streams := m.streams
	m.streams = make(map[string]*activeStream)
	m.state = StreamStateIdle
	m.mu.Unlock()

	for _, stream := range streams {
		if stream != nil && stream.conn != nil {
			_ = stream.conn.Close()
		}
	}
	return nil
}

type StreamRelayEndpoint interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func (s *activeStream) Read(b []byte) (int, error) {
	if s.conn == nil {
		return 0, fmt.Errorf("stream not connected")
	}
	return s.conn.Read(b)
}

func (s *activeStream) Write(b []byte) (int, error) {
	if s.conn == nil {
		return 0, fmt.Errorf("stream not connected")
	}
	return s.conn.Write(b)
}

func (s *activeStream) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *activeStream) LocalAddr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *activeStream) RemoteAddr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.RemoteAddr()
}

func (s *activeStream) SetDeadline(t time.Time) error {
	if s.conn == nil {
		return fmt.Errorf("stream not connected")
	}
	s.deadline = t
	return s.conn.SetDeadline(t)
}

func (s *activeStream) SetReadDeadline(t time.Time) error {
	if s.conn == nil {
		return fmt.Errorf("stream not connected")
	}
	return s.conn.SetReadDeadline(t)
}

func (s *activeStream) SetWriteDeadline(t time.Time) error {
	if s.conn == nil {
		return fmt.Errorf("stream not connected")
	}
	return s.conn.SetWriteDeadline(t)
}

func parseConnectTarget(urlStr string) (host, port string, err error) {
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	host, port, splitErr := net.SplitHostPort(urlStr)
	if splitErr != nil {
		host = urlStr
		port = "443"
	}
	return host, port, nil
}
