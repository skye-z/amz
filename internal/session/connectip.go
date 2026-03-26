package session

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/skye-z/amz/internal/config"
)

const (
	ProtocolConnectIP                   = "connect-ip"
	SessionStateIdle                    = "idle"
	SessionStateReady                   = "ready"
	defaultCloudflareConnectIPAuthority = "cloudflareaccess.com"
)

type ConnectIPOptions struct {
	Authority       string
	Protocol        string
	EnableDatagrams bool
}

type ConnectIPSnapshot struct {
	State    string
	Protocol string
	Endpoint string
	IPv4     string
	IPv6     string
	Routes   []string
}

type SessionInfo struct {
	IPv4   string
	IPv6   string
	Routes []string
}

type ConnectIPSessionManager struct {
	mu      sync.Mutex
	state   string
	options ConnectIPOptions
	quic    QUICOptions
	h3      HTTP3Options
	h3conn  h3ClientConn
	info    SessionInfo
	stats   connectionStats
	compat  *CloudflareCompatLayer
	dialer  connectIPDialer
	session connectIPSession
}

type connectIPSession interface {
	Close() error
	SessionInfo() SessionInfo
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) ([]byte, error)
}

type connectIPSessionInfoWaiter interface {
	WaitForSessionInfo(context.Context) (SessionInfo, error)
}

type connectIPDialer interface {
	Dial(ctx context.Context, h3conn h3ClientConn, quic QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, *http.Response, time.Duration, error)
}

type realConnectIPDialer struct{}

func (d realConnectIPDialer) Dial(ctx context.Context, h3conn h3ClientConn, quicOpts QUICOptions, h3 HTTP3Options, opts ConnectIPOptions) (connectIPSession, *http.Response, time.Duration, error) {
	started := time.Now()
	stream, rsp, err := openCloudflareConnectIPStream(ctx, h3conn, opts)
	if err != nil {
		return nil, rsp, 0, err
	}
	session := newCloudflareConnectIPSession(stream)
	if err := session.sendInitialAddressRequests(); err != nil {
		_ = session.Close()
		return nil, rsp, 0, err
	}
	return session, rsp, time.Since(started), nil
}

func openCloudflareConnectIPStream(ctx context.Context, h3conn h3ClientConn, opts ConnectIPOptions) (h3RequestStream, *http.Response, error) {
	if h3conn == nil || h3conn.RequestConn() == nil {
		return nil, nil, fmt.Errorf("http3 client connection is required")
	}

	requestConn := h3conn.RequestConn()
	rstr, err := requestConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("open request stream: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  opts.Protocol,
		Host:   opts.Authority,
		URL:    &url.URL{Scheme: "http", Host: opts.Authority, Path: "/"},
		Header: make(http.Header),
	}
	req.Header.Set("cf-client-version", defaultMASQUEClientVersion())
	req.Header.Set("pq-enabled", "true")

	if err := rstr.SendRequestHeader(req); err != nil {
		_ = rstr.Close()
		return nil, nil, fmt.Errorf("send request header: %w", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		_ = rstr.Close()
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(rsp.Body, 1024))
		rsp.Body.Close()
		_ = rstr.Close()
		return nil, rsp, fmt.Errorf("connect-ip failed: status=%d body=%s", rsp.StatusCode, string(body))
	}
	return rstr, rsp, nil
}

type cloudflareConnectIPSession struct {
	stream  h3RequestStream
	info    SessionInfo
	closeCh chan struct{}

	mu               sync.Mutex
	assignedPrefixes []netip.Prefix
	availableRoutes  []cloudflareIPRoute
	assignedNotify   chan struct{}
	routesNotify     chan struct{}
	closeErr         error
}

func newCloudflareConnectIPSession(stream h3RequestStream) *cloudflareConnectIPSession {
	s := &cloudflareConnectIPSession{
		stream:         stream,
		closeCh:        make(chan struct{}),
		assignedNotify: make(chan struct{}, 1),
		routesNotify:   make(chan struct{}, 1),
	}
	go s.readCapsules()
	return s
}

func (s *cloudflareConnectIPSession) SessionInfo() SessionInfo { return s.info }

func (s *cloudflareConnectIPSession) WaitForSessionInfo(ctx context.Context) (SessionInfo, error) {
	info, err := s.waitForSessionInfo(ctx)
	if err == nil {
		s.info = info
	}
	return info, err
}

func (s *cloudflareConnectIPSession) waitForSessionInfo(ctx context.Context) (SessionInfo, error) {
	var info SessionInfo
	select {
	case <-ctx.Done():
		return SessionInfo{}, context.Cause(ctx)
	case <-s.closeCh:
		return SessionInfo{}, s.closeErr
	case <-s.assignedNotify:
		s.mu.Lock()
		for _, prefix := range s.assignedPrefixes {
			if prefix.Addr().Is4() && info.IPv4 == "" {
				info.IPv4 = prefix.String()
			}
			if prefix.Addr().Is6() && info.IPv6 == "" {
				info.IPv6 = prefix.String()
			}
		}
		s.mu.Unlock()
	case <-time.After(3 * time.Second):
		// No address assignment capsule received, continue without
	}

	select {
	case <-ctx.Done():
		return SessionInfo{}, context.Cause(ctx)
	case <-s.closeCh:
		return SessionInfo{}, s.closeErr
	case <-s.routesNotify:
		s.mu.Lock()
		info.Routes = make([]string, 0, len(s.availableRoutes))
		for _, route := range s.availableRoutes {
			info.Routes = append(info.Routes, route.StartIP.String()+"-"+route.EndIP.String())
		}
		s.mu.Unlock()
	case <-time.After(1500 * time.Millisecond):
	}
	return info, nil
}

func (s *cloudflareConnectIPSession) sendInitialAddressRequests() error {
	writer := quicvarint.NewWriter(s.stream)
	if err := http3.WriteCapsule(writer, 2, buildAddressRequestPayload()); err != nil {
		return fmt.Errorf("write address request capsule: %w", err)
	}
	return nil
}

func (s *cloudflareConnectIPSession) readCapsules() {
	defer s.fail(io.EOF)
	reader := quicvarint.NewReader(s.stream)
	for {
		capsuleType, capsuleReader, err := http3.ParseCapsule(reader)
		if err != nil {
			s.fail(err)
			return
		}
		switch capsuleType {
		case 1:
			prefixes, err := parseAddressAssignCapsule(capsuleReader)
			if err != nil {
				s.fail(err)
				return
			}
			s.mu.Lock()
			s.assignedPrefixes = prefixes
			s.mu.Unlock()
			select {
			case s.assignedNotify <- struct{}{}:
			default:
			}
		case 3:
			routes, err := parseRouteAdvertisementCapsule(capsuleReader)
			if err != nil {
				s.fail(err)
				return
			}
			s.mu.Lock()
			s.availableRoutes = routes
			s.mu.Unlock()
			select {
			case s.routesNotify <- struct{}{}:
			default:
			}
		default:
			if _, err := io.Copy(io.Discard, capsuleReader); err != nil {
				s.fail(err)
				return
			}
		}
	}
}

func (s *cloudflareConnectIPSession) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil {
		return
	}
	s.closeErr = err
	close(s.closeCh)
}

func (s *cloudflareConnectIPSession) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	data, err := s.stream.ReceiveDatagram(ctx)
	if err != nil {
		select {
		case <-s.closeCh:
			return 0, s.closeErr
		default:
			return 0, err
		}
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, fmt.Errorf("parse datagram context id: %w", err)
	}
	if contextID != 0 {
		return 0, fmt.Errorf("unexpected datagram context id %d", contextID)
	}
	return copy(dst, data[n:]), nil
}

func (s *cloudflareConnectIPSession) WritePacket(ctx context.Context, packet []byte) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	data := make([]byte, 0, len(contextIDZero)+len(packet))
	data = append(data, contextIDZero...)
	data = append(data, packet...)
	if err := s.stream.SendDatagram(data); err != nil {
		select {
		case <-s.closeCh:
			return nil, s.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (s *cloudflareConnectIPSession) Close() error {
	s.fail(io.EOF)
	s.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return s.stream.Close()
}

type cloudflareIPRoute struct {
	StartIP netip.Addr
	EndIP   netip.Addr
}

func parseAddressAssignCapsule(r io.Reader) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for {
		requestID, prefix, err := parseAddress(r)
		_ = requestID
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseAddress(r io.Reader) (uint64, netip.Prefix, error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var addr netip.Addr
	switch ipVersion {
	case 4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		addr = netip.AddrFrom4(raw)
	case 6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		addr = netip.AddrFrom16(raw)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixBits, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	return requestID, netip.PrefixFrom(addr, int(prefixBits)), nil
}

func parseRouteAdvertisementCapsule(r io.Reader) ([]cloudflareIPRoute, error) {
	var routes []cloudflareIPRoute
	for {
		route, err := parseIPAddressRange(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func buildAddressRequestPayload() []byte {
	payload := make([]byte, 0, 32)
	payload = appendAddressRequest(payload, 4, []byte{0, 0, 0, 0}, 0)
	payload = appendAddressRequest(payload, 6, make([]byte, 16), 0)
	return payload
}

func appendAddressRequest(dst []byte, version byte, ip []byte, prefixBits byte) []byte {
	dst = quicvarint.Append(dst, 0)
	dst = append(dst, version)
	dst = append(dst, ip...)
	dst = append(dst, prefixBits)
	return dst
}

func parseIPAddressRange(r io.Reader) (cloudflareIPRoute, error) {
	versionReader := quicvarint.NewReader(r)
	ipVersion, err := versionReader.ReadByte()
	if err != nil {
		return cloudflareIPRoute{}, err
	}
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return cloudflareIPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return cloudflareIPRoute{}, err
		}
		if _, err := versionReader.ReadByte(); err != nil {
			return cloudflareIPRoute{}, err
		}
		return cloudflareIPRoute{StartIP: netip.AddrFrom4(start), EndIP: netip.AddrFrom4(end)}, nil
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return cloudflareIPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return cloudflareIPRoute{}, err
		}
		if _, err := versionReader.ReadByte(); err != nil {
			return cloudflareIPRoute{}, err
		}
		return cloudflareIPRoute{StartIP: netip.AddrFrom16(start), EndIP: netip.AddrFrom16(end)}, nil
	default:
		return cloudflareIPRoute{}, fmt.Errorf("invalid route ip version: %d", ipVersion)
	}
}

func BuildConnectIPOptions(h3 HTTP3Options) ConnectIPOptions {
	return ConnectIPOptions{
		Authority:       defaultCloudflareConnectIPAuthority,
		Protocol:        ProtocolConnectIP,
		EnableDatagrams: h3.EnableDatagrams,
	}
}

func NewConnectIPSessionManager(cfg config.KernelConfig) (*ConnectIPSessionManager, error) {
	quicOpts, err := BuildQUICOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build quic options: %w", err)
	}
	h3 := BuildHTTP3Options(quicOpts)
	compat, err := NewCloudflareCompatLayer(cfg)
	if err != nil {
		return nil, fmt.Errorf("build cloudflare compat: %w", err)
	}
	return &ConnectIPSessionManager{
		state:   SessionStateIdle,
		options: compat.ApplyConnectIPOptions(BuildConnectIPOptions(h3)),
		quic:    quicOpts,
		h3:      h3,
		compat:  compat,
		dialer:  realConnectIPDialer{},
	}, nil
}

func (m *ConnectIPSessionManager) Snapshot() ConnectIPSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ConnectIPSnapshot{
		State:    m.state,
		Protocol: m.options.Protocol,
		Endpoint: m.quic.Endpoint,
		IPv4:     m.info.IPv4,
		IPv6:     m.info.IPv6,
		Routes:   append([]string(nil), m.info.Routes...),
	}
}

func (m *ConnectIPSessionManager) UpdateSessionInfo(info SessionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.info = SessionInfo{
		IPv4:   info.IPv4,
		IPv6:   info.IPv6,
		Routes: append([]string(nil), info.Routes...),
	}
}

func (m *ConnectIPSessionManager) RecordHandshakeLatency(latency time.Duration) {
	m.stats.RecordHandshakeLatency(latency)
}

func (m *ConnectIPSessionManager) AddTxBytes(n int) { m.stats.AddTxBytes(n) }
func (m *ConnectIPSessionManager) AddRxBytes(n int) { m.stats.AddRxBytes(n) }
func (m *ConnectIPSessionManager) Stats() config.Stats {
	return m.stats.Snapshot()
}

func (m *ConnectIPSessionManager) Open(ctx context.Context) error {
	m.mu.Lock()
	if m.session != nil && m.state == SessionStateReady {
		m.mu.Unlock()
		return nil
	}
	dialer := m.dialer
	h3conn := m.h3conn
	quicOpts := m.quic
	h3Opts := m.h3
	opts := m.options
	compat := m.compat
	seedInfo := m.info
	m.mu.Unlock()

	if dialer == nil {
		return fmt.Errorf("connect-ip dialer is required")
	}
	session, rsp, latency, err := dialer.Dial(ctx, h3conn, quicOpts, h3Opts, opts)
	if err != nil {
		if compat != nil {
			return compat.WrapConnectIPError("connect-ip", rsp, err)
		}
		return err
	}

	info := session.SessionInfo()
	if !sessionInfoReady(info) {
		if waiter, ok := session.(connectIPSessionInfoWaiter); ok {
			waited, waitErr := waiter.WaitForSessionInfo(ctx)
			if waitErr == nil && sessionInfoReady(waited) {
				info = waited
			} else if sessionInfoReady(seedInfo) {
				info = seedInfo
			}
			// For proxy mode, session info is optional — the tunnel is already established
		} else if sessionInfoReady(seedInfo) {
			info = seedInfo
		}
	}

	m.mu.Lock()
	m.session = session
	m.state = SessionStateReady
	m.info = info
	m.mu.Unlock()
	m.RecordHandshakeLatency(latency)
	return nil
}

func (m *ConnectIPSessionManager) BindHTTP3Conn(conn h3ClientConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h3conn = conn
}

func sessionInfoReady(info SessionInfo) bool {
	return strings.TrimSpace(info.IPv4) != "" || strings.TrimSpace(info.IPv6) != "" || len(info.Routes) > 0
}

func (m *ConnectIPSessionManager) PacketEndpoint() PacketRelayEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == nil {
		return nil
	}
	return m.session
}

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
