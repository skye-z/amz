package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/packet"
	"github.com/skye-z/amz/internal/testkit"
	internaltun "github.com/skye-z/amz/internal/tun"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	quicParamMasqueVersion      = "masque_version"
	quicVersionDraft08          = "draft-08"
	quicMutatedValue            = "mutated"
	quicExampleTCPAddress       = testkit.TestDomain + ":443"
	quicBootstrapTCPAddress     = testkit.PublicDNSV4 + ":443"
	quicMasqueServerName        = "masque.cloudflareclient.com"
	quicDisconnectReasonTimeout = "timeout"
	quicTracePacketsEnv         = "AMZ_TUN_TRACE_PACKETS"
	quicTraceSourceAddress      = testkit.PacketSrcV4
	quicPayloadPong             = "pong"

	errConnectionManagerCreate = "expected connection manager creation success, got %v"
	errSessionManagerCreate    = "expected session manager creation success, got %v"
	errProtocolMismatch        = "expected protocol %q, got %q"
	errConnectIPManagerCreate  = "expected connect-ip manager creation success, got %v"
	errManagerCreate           = "expected manager creation success, got %v"
	errEndpointMismatch        = "expected endpoint %q, got %q"
	errDatagramsEnabled        = "expected datagrams enabled"
	errCoreTunnelDialerCreate  = "expected core tunnel dialer creation success, got %v"
	errCompatLayerCreate       = "expected compat layer creation success, got %v"
	errServerNameMismatch      = "expected server name %q, got %q"
	errAuthorityMismatch       = "expected authority %q, got %q"
	errExpectedQUICOptions     = "expected quic options, got %v"
)

// 验证 QUIC 连接参数会从内核配置中生成�?
func TestBuildQUICOptions(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errExpectedQUICOptions, err)
	}
	if options.Endpoint != config.DefaultEndpoint {
		t.Fatalf(errEndpointMismatch, config.DefaultEndpoint, options.Endpoint)
	}
	if options.ServerName != config.DefaultSNI {
		t.Fatalf(errServerNameMismatch, config.DefaultSNI, options.ServerName)
	}
	if options.EnableDatagrams != true {
		t.Fatal(errDatagramsEnabled)
	}
}

// 验证 QUIC 参数构造会补齐默认值并保持最小传输开关�?
func TestBuildQUICOptionsAppliesDefaults(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected quic options with defaults, got %v", err)
	}
	if options.Endpoint != config.DefaultEndpoint {
		t.Fatalf(errEndpointMismatch, config.DefaultEndpoint, options.Endpoint)
	}
	if options.ServerName != config.DefaultSNI {
		t.Fatalf(errServerNameMismatch, config.DefaultSNI, options.ServerName)
	}
	if options.Keepalive != config.DefaultKeepalive.String() {
		t.Fatalf("expected keepalive %q, got %q", config.DefaultKeepalive.String(), options.Keepalive)
	}
	if !options.EnableDatagrams {
		t.Fatal(errDatagramsEnabled)
	}
}

// 验证 HTTP/3 连接参数会复�?QUIC 连接信息�?
func TestBuildHTTP3Options(t *testing.T) {
	http3Options := BuildHTTP3Options(QUICOptions{
		Endpoint:        config.DefaultEndpoint,
		ServerName:      config.DefaultSNI,
		EnableDatagrams: true,
	})
	if http3Options.Authority != config.DefaultEndpoint {
		t.Fatalf(errAuthorityMismatch, config.DefaultEndpoint, http3Options.Authority)
	}
	if !http3Options.EnableDatagrams {
		t.Fatal(errDatagramsEnabled)
	}
}

// 验证 QUIC 连接参数会预留拥塞控制与连接参数扩展点�?
func TestBuildQUICOptionsWithExtensions(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
		QUIC: config.QUICConfig{
			CongestionControl: "bbr",
			ConnectionParameters: map[string]string{
				"max_streams": "16",
			},
		},
	})
	if err != nil {
		t.Fatalf(errExpectedQUICOptions, err)
	}
	if options.CongestionControl != "bbr" {
		t.Fatalf("expected congestion control %q, got %q", "bbr", options.CongestionControl)
	}
	if got := options.ConnectionParameters["max_streams"]; got != "16" {
		t.Fatalf("expected connection parameter %q, got %q", "16", got)
	}
}

// 验证 QUIC 参数会复制配置中的连接参数，避免后续变更污染传输层快照�?
func TestBuildQUICOptionsCopiesConfigConnectionParameters(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
		QUIC: config.QUICConfig{
			ConnectionParameters: map[string]string{
				quicParamMasqueVersion: quicVersionDraft08,
			},
		},
	}

	options, err := BuildQUICOptions(cfg)
	if err != nil {
		t.Fatalf(errExpectedQUICOptions, err)
	}

	cfg.QUIC.ConnectionParameters[quicParamMasqueVersion] = quicMutatedValue
	if got := options.ConnectionParameters[quicParamMasqueVersion]; got != quicVersionDraft08 {
		t.Fatalf("expected copied connection parameter %q, got %q", quicVersionDraft08, got)
	}
}

// 验证 HTTP/3 连接参数会继承并隔离 QUIC 连接扩展参数�?
func TestBuildHTTP3OptionsCopiesConnectionParameters(t *testing.T) {
	http3Options := BuildHTTP3Options(QUICOptions{
		Endpoint:        config.DefaultEndpoint,
		ServerName:      config.DefaultSNI,
		EnableDatagrams: true,
		ConnectionParameters: map[string]string{
			quicParamMasqueVersion: quicVersionDraft08,
		},
	})
	if got := http3Options.ConnectionParameters[quicParamMasqueVersion]; got != quicVersionDraft08 {
		t.Fatalf("expected connection parameter %q, got %q", quicVersionDraft08, got)
	}
	http3Options.ConnectionParameters[quicParamMasqueVersion] = "changed"
	quicOptions := QUICOptions{
		ConnectionParameters: map[string]string{
			quicParamMasqueVersion: quicVersionDraft08,
		},
	}
	isolated := BuildHTTP3Options(quicOptions)
	isolated.ConnectionParameters[quicParamMasqueVersion] = "changed"
	if quicOptions.ConnectionParameters[quicParamMasqueVersion] != quicVersionDraft08 {
		t.Fatal("expected http3 connection parameters to be copied")
	}
}

// 验证连接管理器会暴露最小状态快照�?
func TestConnectionManagerSnapshot(t *testing.T) {
	manager, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errManagerCreate, err)
	}
	snapshot := manager.Snapshot()
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf(errEndpointMismatch, config.DefaultEndpoint, snapshot.Endpoint)
	}
	if snapshot.State != ConnStateIdle {
		t.Fatalf("expected idle state, got %q", snapshot.State)
	}
}

// 验证连接管理器会暴露基础连接统计入口�?
func TestConnectionManagerStats(t *testing.T) {
	manager, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errManagerCreate, err)
	}

	manager.RecordHandshakeLatency(120 * time.Millisecond)
	manager.AddTxBytes(128)
	manager.AddRxBytes(256)

	stats := manager.Stats()
	if stats.HandshakeLatency != 120*time.Millisecond {
		t.Fatalf("expected handshake latency 120ms, got %s", stats.HandshakeLatency)
	}
	if stats.TxBytes != 128 {
		t.Fatalf("expected tx bytes 128, got %d", stats.TxBytes)
	}
	if stats.RxBytes != 256 {
		t.Fatalf("expected rx bytes 256, got %d", stats.RxBytes)
	}
}

func TestNewBootstrapDialerDelegatesToCoreTunnelDialer(t *testing.T) {
	cfg := config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeHTTP, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, HTTP: config.HTTPConfig{ListenAddress: config.DefaultHTTPListenAddress}}
	connMgr, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectionManagerCreate, err)
	}
	sessMgr, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}
	dialer, err := NewBootstrapDialer(connMgr, sessMgr, nil)
	if err != nil {
		t.Fatalf("expected bootstrap dialer creation success, got %v", err)
	}
	if dialer == nil || dialer.StreamManager() == nil {
		t.Fatal("expected initialized bootstrap dialer")
	}
}

func TestPacketStackDialerValidationAndHelpers(t *testing.T) {
	if _, err := NewPacketStackDialer(nil); err == nil {
		t.Fatal("expected nil bootstrap error")
	}
	dialer, err := NewPacketStackDialer(&fakePacketBootstrap{prepareErr: context.Canceled})
	if err != nil {
		t.Fatalf("expected dialer creation success, got %v", err)
	}
	if _, err := dialer.DialContext(context.Background(), "udp", testkit.PublicDNSV4+":53"); err == nil {
		t.Fatal("expected non-tcp network error")
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "missing-port"); err == nil {
		t.Fatal("expected malformed target error")
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", quicExampleTCPAddress); err == nil {
		t.Fatal("expected prepare/cause error")
	}
	if local4, local6, err := parsePacketLocalAddrs(SessionInfo{}); err == nil || local4.IsValid() || local6.IsValid() {
		t.Fatalf("expected missing address error, got local4=%v local6=%v err=%v", local4, local6, err)
	}
	if _, _, err := parsePacketLocalAddrs(SessionInfo{IPv4: "bad-prefix"}); err == nil {
		t.Fatal("expected invalid ipv4 prefix error")
	}
	if _, _, err := parsePacketLocalAddrs(SessionInfo{IPv6: "bad-prefix"}); err == nil {
		t.Fatal("expected invalid ipv6 prefix error")
	}
}

func TestPacketStackLinkEndpointBasicMethods(t *testing.T) {
	endpoint := &packetStackLinkEndpoint{mtu: 1400}
	if endpoint.MTU() != 1400 {
		t.Fatalf("expected mtu 1400, got %d", endpoint.MTU())
	}
	if endpoint.MaxHeaderLength() != 0 || endpoint.LinkAddress() != "" || endpoint.IsAttached() {
		t.Fatalf("unexpected default endpoint values")
	}
	endpoint.Attach(nil)
	if endpoint.IsAttached() {
		t.Fatal("expected unattached endpoint when dispatcher nil")
	}
	endpoint.Wait()
	endpoint.Close()
	endpoint.SetOnCloseAction(nil)
	if !endpoint.ParseHeader(nil) {
		t.Fatal("expected parse header passthrough")
	}
	endpoint.AddHeader(nil)
	if endpoint.ARPHardwareType() == 0 {
		// expected ARPHardwareNone; asserting method is callable
	}
}

func TestPacketStackLinkEndpointReadLoopAndWritePackets(t *testing.T) {
	relay := newFakeSessionPacketEndpoint()
	endpoint := &packetStackLinkEndpoint{
		endpoint:   relay,
		readPacket: func(buf []byte) (int, error) { return relay.ReadPacket(context.Background(), buf) },
		writePacket: func(packet []byte) error {
			_, err := relay.WritePacket(context.Background(), packet)
			return err
		},
		mtu: 1280,
	}
	dispatcher := &fakeNetworkDispatcher{delivered: make(chan tcpip.NetworkProtocolNumber, 1)}
	endpoint.Attach(dispatcher)
	relay.enqueueRead([]byte{0x45, 0x00, 0x00, 0x00})
	select {
	case protocol := <-dispatcher.delivered:
		if protocol == 0 {
			t.Fatal("expected delivered protocol")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected packet delivery from readLoop")
	}

	var list stack.PacketBufferList
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x00})})
	list.PushBack(packet)
	written, err := endpoint.WritePackets(list)
	packet.DecRef()
	if err != nil || written != 1 {
		t.Fatalf("expected write packets success, got written=%d err=%v", written, err)
	}
	if len(relay.writes) != 1 {
		t.Fatalf("expected relay write capture, got %+v", relay.writes)
	}
	_ = relay.Close()
}

func TestConnectionStatsAliasAndRuntimeInterfaces(t *testing.T) {
	stats := &connectionStats{}
	stats.RecordHandshakeLatency(time.Millisecond)
	stats.AddTxBytes(10)
	stats.AddRxBytes(20)
	if snap := stats.Snapshot(); snap.TxBytes != 10 || snap.RxBytes != 20 {
		t.Fatalf("unexpected stats snapshot: %+v", snap)
	}
	var _ HTTPStreamDialer = httpStreamDialerStub{}
	var _ TUNDevice = tunDeviceStub{}
}

func TestCloudflareCompatLayerAdditionalBranches(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf(errCompatLayerCreate, err)
	}
	if got := layer.Snapshot(); got.Endpoint == "" {
		t.Fatalf("expected snapshot endpoint, got %+v", got)
	}
	if err := layer.WrapConnectStreamError("connect-stream", nil, errors.New("server didn't enable extended connect")); err == nil {
		t.Fatal("expected wrapped connect-stream error")
	}
	if err := layer.WrapConnectStreamError("connect-stream", nil, context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error passthrough, got %v", err)
	}
	if got := classifyCloudflareStatus(404); got != CloudflareQuirkRouteUnavailable {
		t.Fatalf("unexpected route quirk: %q", got)
	}
	if got := classifyCloudflareStatus(400); got != CloudflareQuirkProtocolMismatch {
		t.Fatalf("unexpected protocol quirk: %q", got)
	}
	if got := classifyCloudflareProtocolError(errors.New("extended connect not enabled")); got != CloudflareQuirkMissingExtendedConnect {
		t.Fatalf("unexpected protocol classification: %q", got)
	}
	if got := classifyCloudflareProtocolError(errors.New("capsule missing")); got != CloudflareQuirkProtocolMismatch {
		t.Fatalf("unexpected capsule classification: %q", got)
	}
}

func TestConnectStreamHelpersAndActiveStreamBranches(t *testing.T) {
	if got := staticAddr(quicBootstrapTCPAddress).Network(); got != "tcp" {
		t.Fatalf("unexpected network: %q", got)
	}
	if got := staticAddr(quicBootstrapTCPAddress).String(); got != quicBootstrapTCPAddress {
		t.Fatalf("unexpected addr string: %q", got)
	}
	manager, err := NewConnectStreamManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: config.DefaultHTTPListenAddress},
	})
	if err != nil {
		t.Fatalf("expected stream manager creation success, got %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	manager.streams[quicExampleTCPAddress] = &activeStream{
		conn:   client,
		info:   StreamInfo{RemoteAddr: "old", Protocol: "proto"},
		local:  "local",
		remote: "remote",
	}
	manager.UpdateStreamInfo(quicExampleTCPAddress, StreamInfo{RemoteAddr: "new", Protocol: ProtocolConnectStream})
	if manager.StreamEndpoint(testkit.TestDomain, "443") == nil {
		t.Fatal("expected stream endpoint after update")
	}
	stream := manager.streams[quicExampleTCPAddress]
	if stream.info.RemoteAddr != "new" {
		t.Fatalf("expected updated stream info, got %+v", stream.info)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte(quicPayloadPong))
	}()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("expected stream write success, got %v", err)
	}
	buf := make([]byte, 4)
	if _, err := stream.Read(buf); err != nil || string(buf) != quicPayloadPong {
		t.Fatalf("expected stream read success, got %q err=%v", string(buf), err)
	}
	if stream.LocalAddr() == nil || stream.RemoteAddr() == nil {
		t.Fatal("expected stream addresses")
	}
	if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected SetDeadline success, got %v", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected SetReadDeadline success, got %v", err)
	}
	if err := stream.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected SetWriteDeadline success, got %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("expected stream close success, got %v", err)
	}
	<-done
}

func TestCoreTunnelDialerAdditionalHelpers(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP:           config.HTTPConfig{ListenAddress: config.DefaultHTTPListenAddress},
	}
	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectionManagerCreate, err)
	}
	connectionManager.dialer = &countingTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}}
	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectIPManagerCreate, err)
	}
	sessionManager.dialer = &countingConnectIPDialer{session: &fakePacketSession{}}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, &stubHTTPStreamDialer{})
	if err != nil {
		t.Fatalf("expected core dialer creation success, got %v", err)
	}
	reported := make(chan failure.Event, 1)
	dialer.SetFailureReporter(func(event failure.Event) { reported <- event })
	if err := dialer.PrepareStream(context.Background()); err != nil {
		t.Fatalf("expected PrepareStream success, got %v", err)
	}
	if err := dialer.Prepare(context.Background()); err != nil {
		t.Fatalf("expected Prepare success, got %v", err)
	}
	if info := dialer.SessionInfo(); info.IPv4 == "" {
		t.Fatalf("expected session info from core dialer, got %+v", info)
	}
	if dialer.PacketEndpoint() == nil {
		t.Fatal("expected packet endpoint from core dialer")
	}
	dialer.reportFailure(errors.New("boom"))
	select {
	case event := <-reported:
		if event.Component != failure.ComponentSession {
			t.Fatalf("unexpected failure event: %+v", event)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected reported failure event")
	}
}

type fakePacketBootstrap struct {
	prepareErr error
}

func (b *fakePacketBootstrap) Prepare(context.Context) error       { return b.prepareErr }
func (b *fakePacketBootstrap) SessionInfo() SessionInfo            { return SessionInfo{} }
func (b *fakePacketBootstrap) PacketEndpoint() PacketRelayEndpoint { return nil }
func (b *fakePacketBootstrap) Close() error                        { return nil }

type httpStreamDialerStub struct{}

func (httpStreamDialerStub) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

type tunDeviceStub struct{}

func (tunDeviceStub) Name() string                                     { return "amz0" }
func (tunDeviceStub) MTU() int                                         { return 1280 }
func (tunDeviceStub) ReadPacket(context.Context, []byte) (int, error)  { return 0, nil }
func (tunDeviceStub) WritePacket(context.Context, []byte) (int, error) { return 0, nil }
func (tunDeviceStub) Close() error                                     { return nil }

type fakeSessionPacketEndpoint struct {
	readCh  chan []byte
	closeCh chan struct{}
	writes  [][]byte
}

func newFakeSessionPacketEndpoint() *fakeSessionPacketEndpoint {
	return &fakeSessionPacketEndpoint{
		readCh:  make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
}

func (e *fakeSessionPacketEndpoint) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-e.closeCh:
		return 0, context.Canceled
	case packet := <-e.readCh:
		return copy(dst, packet), nil
	}
}

func (e *fakeSessionPacketEndpoint) WritePacket(context.Context, []byte) ([]byte, error) {
	e.writes = append(e.writes, []byte{0x45, 0x00, 0x00, 0x00})
	return nil, nil
}

func (e *fakeSessionPacketEndpoint) Close() error {
	select {
	case <-e.closeCh:
	default:
		close(e.closeCh)
	}
	return nil
}

func (e *fakeSessionPacketEndpoint) enqueueRead(packet []byte) {
	e.readCh <- append([]byte(nil), packet...)
}

type fakeNetworkDispatcher struct {
	delivered chan tcpip.NetworkProtocolNumber
}

func (d *fakeNetworkDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	select {
	case d.delivered <- protocol:
	default:
	}
}

func (d *fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	// No-op: these tests only assert network-layer delivery.
}

type datagramTestStream struct {
	fakeRequestStream
	sentDatagram []byte
	receive      []byte
	receiveErr   error
	cancelCalled bool
}

func (s *datagramTestStream) SendDatagram(b []byte) error {
	s.sentDatagram = append([]byte(nil), b...)
	return s.writeErr
}

func (s *datagramTestStream) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.receiveErr != nil {
		return nil, s.receiveErr
	}
	return append([]byte(nil), s.receive...), nil
}

func (s *datagramTestStream) CancelRead(quic.StreamErrorCode) { s.cancelCalled = true }

type waiterSession struct {
	fakeConnectIPSession
	waitErr error
}

func (s *waiterSession) WaitForSessionInfo(context.Context) (SessionInfo, error) {
	return SessionInfo{}, s.waitErr
}

func TestQUICHelperBranches(t *testing.T) {
	cfg := buildQUICConfig(QUICOptions{EnableDatagrams: true})
	if !cfg.EnableDatagrams || cfg.MaxIdleTimeout == 0 || cfg.KeepAlivePeriod == 0 {
		t.Fatalf("unexpected quic config: %+v", cfg)
	}
	if got := tlsServerNameForOptions(QUICOptions{ServerName: testkit.TestDomain, Endpoint: quicBootstrapTCPAddress}); got != testkit.TestDomain {
		t.Fatalf("unexpected server name: %q", got)
	}
	if requiresPinnedMASQUETrust(QUICOptions{PeerPublicKey: "pk", Endpoint: quicBootstrapTCPAddress}) {
		t.Fatal("expected :443 not to require pinned trust")
	}
	if !requiresPinnedMASQUETrust(QUICOptions{PeerPublicKey: "pk", Endpoint: testkit.PublicDNSV4 + ":8443"}) {
		t.Fatal("expected alternate port to require pinned trust")
	}
	if got := normalizePEM(" a\n\n b "); got != "a\nb" {
		t.Fatalf("unexpected normalized pem: %q", got)
	}
}

func TestRealTransportDialerInvalidEndpointAndClientCertificateHelpers(t *testing.T) {
	if _, _, _, err := (realTransportDialer{}).Dial(context.Background(), QUICOptions{Endpoint: "not-an-endpoint"}, HTTP3Options{}); err == nil {
		t.Fatal("expected invalid endpoint dial error")
	}
	if cert, err := buildClientCertificate(QUICOptions{}); err != nil || cert != nil {
		t.Fatalf("expected nil client certificate on empty materials, got cert=%v err=%v", cert, err)
	}
	if _, err := parseECDSAPrivateKey("not-base64"); err == nil {
		t.Fatal("expected parseECDSAPrivateKey error")
	}
	if _, err := NewConnectionManager(config.KernelConfig{MTU: 1}); err == nil {
		t.Fatal("expected invalid connection manager config error")
	}
}

func TestOpenCloudflareConnectIPStreamErrorBranches(t *testing.T) {
	if _, _, err := openCloudflareConnectIPStream(context.Background(), nil, ConnectIPOptions{}); err == nil {
		t.Fatal("expected nil http3 connection error")
	}

	_, _, err := openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{openErr: errors.New("open fail")}}, ConnectIPOptions{})
	if err == nil || !strings.Contains(err.Error(), "open request stream") {
		t.Fatalf("expected open request stream error, got %v", err)
	}

	stream := &fakeRequestStream{sendErr: errors.New("send fail")}
	_, _, err = openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: testkit.TestDomain, Protocol: ProtocolConnectIP})
	if err == nil || !strings.Contains(err.Error(), "send request header") || !stream.closed {
		t.Fatalf("expected send header error and closed stream, got err=%v closed=%v", err, stream.closed)
	}

	stream = &fakeRequestStream{readResponseErr: errors.New("read fail")}
	_, _, err = openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: testkit.TestDomain, Protocol: ProtocolConnectIP})
	if err == nil || !strings.Contains(err.Error(), "read response") || !stream.closed {
		t.Fatalf("expected read response error and closed stream, got err=%v closed=%v", err, stream.closed)
	}

	stream = &fakeRequestStream{response: &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad gateway"))}}
	_, rsp, err := openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: testkit.TestDomain, Protocol: ProtocolConnectIP})
	if err == nil || rsp == nil || !strings.Contains(err.Error(), "status=502") || !strings.Contains(err.Error(), "bad gateway") || !stream.closed {
		t.Fatalf("expected non-2xx error and closed stream, got rsp=%v err=%v closed=%v", rsp, err, stream.closed)
	}
}

func TestCloudflareConnectIPSessionDatagramAndCloseBranches(t *testing.T) {
	stream := &datagramTestStream{receive: append(append([]byte(nil), contextIDZero...), []byte(quicPayloadPong)...)}
	session := &cloudflareConnectIPSession{
		stream:         stream,
		closeCh:        make(chan struct{}),
		assignedNotify: make(chan struct{}, 1),
		routesNotify:   make(chan struct{}, 1),
	}

	if _, err := session.WritePacket(context.Background(), []byte("ping")); err != nil {
		t.Fatalf("expected WritePacket success, got %v", err)
	}
	if string(stream.sentDatagram[len(contextIDZero):]) != "ping" {
		t.Fatalf("expected sent datagram payload, got %v", stream.sentDatagram)
	}
	buf := make([]byte, 8)
	if n, err := session.ReadPacket(context.Background(), buf); err != nil || string(buf[:n]) != quicPayloadPong {
		t.Fatalf("expected ReadPacket success, got n=%d err=%v payload=%q", n, err, string(buf[:n]))
	}

	stream.receive = quicvarint.Append(nil, 1)
	if _, err := session.ReadPacket(context.Background(), buf); err == nil || !strings.Contains(err.Error(), "unexpected datagram context id") {
		t.Fatalf("expected unexpected context id error, got %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.WritePacket(canceledCtx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled write error, got %v", err)
	}

	session.fail(io.EOF)
	stream.receiveErr = errors.New("datagram failed")
	if _, err := session.ReadPacket(context.Background(), buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected closed session read error, got %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("expected session close success, got %v", err)
	}
	if !stream.cancelCalled || !stream.closed {
		t.Fatalf("expected cancel+close on stream, got cancel=%v closed=%v", stream.cancelCalled, stream.closed)
	}
}

func TestConnectIPSessionManagerOpenAndParsingBranches(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}
	manager.dialer = nil
	if err := manager.Open(context.Background()); err == nil {
		t.Fatal("expected nil dialer open error")
	}

	manager, err = NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: config.DefaultSOCKSListenAddress},
	})
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}
	seedIPv4CIDR := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32).String()
	manager.info = SessionInfo{IPv4: seedIPv4CIDR}
	manager.dialer = &fakeConnectIPDialer{session: &waiterSession{waitErr: errors.New("no info")}}
	if err := manager.Open(context.Background()); err != nil {
		t.Fatalf("expected open success with seed info fallback, got %v", err)
	}
	if manager.Snapshot().IPv4 != seedIPv4CIDR {
		t.Fatalf("expected seed info fallback in snapshot, got %+v", manager.Snapshot())
	}

	if _, err := parseIPAddressRange(strings.NewReader(string([]byte{9}))); err == nil {
		t.Fatal("expected invalid route ip version error")
	}
}

func TestHTTP3AdaptersAndConnectionManagerHelpers(t *testing.T) {
	connAdapter := &http3ClientConnAdapter{}
	if connAdapter.Raw() != nil || connAdapter.RequestConn() != nil {
		t.Fatal("expected nil raw/request conn when adapter conn missing")
	}
	if err := connAdapter.AwaitSettings(context.Background(), false, false); err != nil {
		t.Fatalf("expected await settings no-op, got %v", err)
	}
	qc := &quicConnAdapter{conn: nil}
	if qc == nil {
		t.Fatal("expected adapter instance")
	}

	mgr, err := NewConnectionManager(config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeHTTP, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, HTTP: config.HTTPConfig{ListenAddress: config.DefaultHTTPListenAddress}})
	if err != nil {
		t.Fatalf(errConnectionManagerCreate, err)
	}
	if mgr.HTTP3Conn() != nil {
		t.Fatal("expected nil h3 conn before connect")
	}
	if got := mgr.Stats(); got.HandshakeLatency != 0 || got.TxBytes != 0 || got.RxBytes != 0 {
		t.Fatalf("unexpected initial stats: %+v", got)
	}
}

const (
	preparedStreamTestTargetHost = testkit.TestDomain
	preparedStreamTestTargetPort = "443"
)

func TestPreparedConnectStreamOpenerPreparesBeforeOpen(t *testing.T) {
	t.Parallel()

	preparer := &stubStreamPreparer{}
	manager := &stubPreparedStreamManager{}
	opener := NewPreparedConnectStreamOpener(preparer, manager)

	conn, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if err != nil {
		t.Fatalf("expected open stream success, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil stream connection")
	}
	if !preparer.called {
		t.Fatal("expected PrepareStream to be called before OpenStream")
	}
	if !manager.called {
		t.Fatal("expected underlying stream manager to be called")
	}
	if manager.host != preparedStreamTestTargetHost || manager.port != preparedStreamTestTargetPort {
		t.Fatalf("unexpected target %s:%s", manager.host, manager.port)
	}
}

func TestPreparedConnectStreamOpenerReturnsPrepareError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("prepare failed")
	opener := NewPreparedConnectStreamOpener(&stubStreamPreparer{err: wantErr}, &stubPreparedStreamManager{})

	_, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected prepare error %v, got %v", wantErr, err)
	}
}

func TestPreparedProxyStreamOpenerUsesConnectStreamProtocol(t *testing.T) {
	t.Parallel()

	stream := &fakeRequestStream{
		response: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody},
	}
	manager, err := NewConnectStreamManager(testConnectStreamConfig())
	if err != nil {
		t.Fatalf(errManagerCreate, err)
	}
	manager.h3conn = &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}
	manager.SetReady()

	opener := NewPreparedProxyStreamOpener(nil, manager)
	conn, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if err != nil {
		t.Fatalf("expected proxy stream open success, got %v", err)
	}
	_ = conn.Close()

	if stream.request == nil {
		t.Fatal("expected CONNECT request to be sent")
	}
	if stream.request.Proto != ProtocolConnectStream {
		t.Fatalf("expected connect-stream protocol token, got %q", stream.request.Proto)
	}
}

type stubStreamPreparer struct {
	called bool
	err    error
}

func (s *stubStreamPreparer) PrepareStream(context.Context) error {
	s.called = true
	return s.err
}

type stubPreparedStreamManager struct {
	called bool
	host   string
	port   string
}

func (s *stubPreparedStreamManager) OpenStream(_ context.Context, host, port string) (net.Conn, error) {
	s.called = true
	s.host = host
	s.port = port
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func testConnectStreamConfig() config.KernelConfig {
	cfg := config.KernelConfig{
		Mode:     config.ModeHTTP,
		Endpoint: testkit.WarpIPv4Legacy443,
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()
	return cfg
}

// 验证退避策略会限制重试次数并计算等待时间�?
func TestRetryPolicyBackoff(t *testing.T) {
	policy := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    5 * time.Second,
	}
	if !policy.Allow(2) {
		t.Fatal("expected attempt 2 to be allowed")
	}
	if policy.Allow(4) {
		t.Fatal("expected attempt 4 to be rejected")
	}
	if delay := policy.Backoff(3); delay != 3*time.Second {
		t.Fatalf("expected backoff 3s, got %s", delay)
	}
}

// 验证连接事件会携带状态与原因�?
func TestConnectionEvent(t *testing.T) {
	event := ConnectionEvent{
		State:   ConnStateConnecting,
		Reason:  "reconnect",
		Attempt: 2,
	}
	if event.State != ConnStateConnecting {
		t.Fatalf("expected state %q, got %q", ConnStateConnecting, event.State)
	}
	if event.Reason != "reconnect" {
		t.Fatalf("expected reason reconnect, got %q", event.Reason)
	}
}

// 验证保活管理器会输出状态变化事件�?
func TestKeepaliveManagerEvents(t *testing.T) {
	manager := NewKeepaliveManager(RetryPolicy{
		MaxAttempts: 2,
		BaseDelay:   1 * time.Second,
		MaxDelay:    3 * time.Second,
	})

	manager.MarkConnected()
	manager.MarkDisconnected(quicDisconnectReasonTimeout)
	events := manager.Events()

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].State != ConnStateReady {
		t.Fatalf("expected ready event, got %q", events[0].State)
	}
	if events[1].Reason != quicDisconnectReasonTimeout {
		t.Fatalf("expected timeout reason, got %q", events[1].Reason)
	}
}

// 验证保活管理器会累积重连次数统计�?
func TestKeepaliveManagerReconnectStats(t *testing.T) {
	manager := NewKeepaliveManager(RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    5 * time.Second,
	})

	manager.RecordReconnect(quicDisconnectReasonTimeout, 2)

	stats := manager.Stats()
	if stats.ReconnectCount != 1 {
		t.Fatalf("expected reconnect count 1, got %d", stats.ReconnectCount)
	}

	events := manager.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Attempt != 2 {
		t.Fatalf("expected attempt 2, got %d", events[0].Attempt)
	}
	if events[0].Reason != quicDisconnectReasonTimeout {
		t.Fatalf("expected timeout reason, got %q", events[0].Reason)
	}
}

func TestRetryPolicyAdditionalBranchesAndEventCopy(t *testing.T) {
	policy := RetryPolicy{
		MaxAttempts: 0,
		BaseDelay:   1 * time.Second,
		MaxDelay:    1500 * time.Millisecond,
	}
	if policy.Allow(1) {
		t.Fatal("expected zero-attempt policy to reject retries")
	}
	if delay := policy.Backoff(0); delay != 0 {
		t.Fatalf("expected zero backoff, got %s", delay)
	}

	manager := NewKeepaliveManager(RetryPolicy{
		MaxAttempts: 2,
		BaseDelay:   1 * time.Second,
		MaxDelay:    1500 * time.Millisecond,
	})
	manager.MarkConnected()
	manager.MarkDisconnected(quicDisconnectReasonTimeout)
	events := manager.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	events[0].State = quicMutatedValue
	if manager.Events()[0].State != ConnStateReady {
		t.Fatalf("expected event slice copy, got %+v", manager.Events())
	}
	if delay := manager.policy.Backoff(3); delay != 1500*time.Millisecond {
		t.Fatalf("expected capped backoff, got %s", delay)
	}
}

// 验证会话管理器可保存地址与路由信息�?
func TestConnectIPSessionManagerUpdateSessionInfo(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errManagerCreate, err)
	}

	manager.UpdateSessionInfo(SessionInfo{
		IPv4:   testkit.TunIPv4CIDR,
		IPv6:   testkit.TunIPv6AltCIDR,
		Routes: []string{testkit.DefaultRouteV4, testkit.DefaultRouteV6},
	})

	snapshot := manager.Snapshot()
	if snapshot.IPv4 != testkit.TunIPv4CIDR {
		t.Fatalf("expected ipv4 in snapshot, got %q", snapshot.IPv4)
	}
	if snapshot.IPv6 != testkit.TunIPv6AltCIDR {
		t.Fatalf("expected ipv6 in snapshot, got %q", snapshot.IPv6)
	}
	if len(snapshot.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(snapshot.Routes))
	}
}

func TestConnectionStatsUsesTypesAlias(t *testing.T) {
	stats := &connectionStats{}
	stats.RecordHandshakeLatency(25 * time.Millisecond)
	stats.AddTxBytes(64)
	stats.AddRxBytes(32)

	snapshot := stats.Snapshot()
	if snapshot.HandshakeLatency != 25*time.Millisecond || snapshot.TxBytes != 64 || snapshot.RxBytes != 32 {
		t.Fatalf("unexpected stats snapshot: %+v", snapshot)
	}
	if _, ok := any(stats).(*config.ConnectionStats); !ok {
		t.Fatalf("expected connection stats to use config alias, got %T", stats)
	}
}

func TestDefaultCloudflareQuirksUsesInternalAlias(t *testing.T) {
	quirks := DefaultCloudflareQuirks()
	if _, ok := any(quirks).(internalcloudflare.Quirks); !ok {
		t.Fatalf("expected cloudflare quirks to use internal alias, got %T", quirks)
	}
	if quirks.Name == "" || !quirks.UseCFConnectIP || !quirks.RequireDatagrams {
		t.Fatalf("unexpected default quirks: %+v", quirks)
	}
}

func TestCloudflareSnapshotUsesInternalAlias(t *testing.T) {
	snapshot := CloudflareSnapshot{Protocol: ProtocolCFConnectIP, Endpoint: testkit.WarpIPv4Alt443}
	if _, ok := any(snapshot).(internalcloudflare.Snapshot); !ok {
		t.Fatalf("expected cloudflare snapshot to use internal alias, got %T", snapshot)
	}
	if snapshot.Protocol != internalcloudflare.ProtocolCFConnectIP {
		t.Fatalf(errProtocolMismatch, internalcloudflare.ProtocolCFConnectIP, snapshot.Protocol)
	}
}

func TestCloudflareCompatLayerDefaultsWithoutPublicImpl(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf(errCompatLayerCreate, err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != internalcloudflare.ProtocolCFConnectIP {
		t.Fatalf(errProtocolMismatch, internalcloudflare.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf(errEndpointMismatch, config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}

func TestCloudflareCompatLayerWrapsProtocolErrorWithoutPublicImpl(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf(errCompatLayerCreate, err)
	}

	err = layer.WrapProtocolError("connect-ip", errors.New("http3 settings: datagrams not enabled"))
	if !errors.Is(err, internalcloudflare.ErrCompat) {
		t.Fatalf("expected cloudflare compat error, got %v", err)
	}
	var compatErr *internalcloudflare.CompatError
	if !errors.As(err, &compatErr) {
		t.Fatal("expected contextual cloudflare compat error")
	}
	if compatErr.Quirk != internalcloudflare.CloudflareQuirkMissingDatagrams {
		t.Fatalf("expected quirk %q, got %q", internalcloudflare.CloudflareQuirkMissingDatagrams, compatErr.Quirk)
	}
	wrapped := layer.WrapConnectIPError("connect-ip", &http.Response{StatusCode: http.StatusTooManyRequests}, errors.New("rate limited"))
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected contextual connect-ip compat error")
	}
	if compatErr.Quirk != internalcloudflare.CloudflareQuirkRateLimited {
		t.Fatalf("expected quirk %q, got %q", internalcloudflare.CloudflareQuirkRateLimited, compatErr.Quirk)
	}
}

func TestCloudflareCompatLayerDoesNotExposePublicImplType(t *testing.T) {
	layerType := reflect.TypeOf(CloudflareCompatLayer{})
	if _, ok := layerType.FieldByName("impl"); ok {
		t.Fatal("expected session compat layer to drop public impl field")
	}
	for i := 0; i < layerType.NumField(); i++ {
		if strings.Contains(layerType.Field(i).Type.String(), "cloudflare.CompatLayer") {
			t.Fatalf("expected session compat layer to avoid public cloudflare impl type, got %s", layerType.Field(i).Type.String())
		}
	}
}

func TestCloudflareCompatLayerLoopbackAndResponseBranches(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{Endpoint: "127.0.0.1:443"})
	if err != nil {
		t.Fatalf("expected loopback compat layer success, got %v", err)
	}
	if layer.Snapshot().Quirks.UseCFConnectIP {
		t.Fatalf("expected loopback endpoint to disable CF connect-ip quirk, got %+v", layer.Snapshot())
	}

	var nilLayer *CloudflareCompatLayer
	if got := nilLayer.Snapshot(); got.Protocol != "" || got.Endpoint != "" {
		t.Fatalf("expected zero snapshot for nil layer, got %+v", got)
	}
	if err := nilLayer.WrapResponseError("op", http.StatusBadGateway, errors.New("boom")); err == nil {
		t.Fatal("expected nil layer to return original cause")
	}
}

// 验证协议参数映射会以表驱动方式覆盖 CONNECT-IP 协议解析结果。
func TestBuildConnectIPOptionsTableDriven(t *testing.T) {
	tests := []struct {
		name string
		h3   HTTP3Options
	}{
		{
			name: "datagrams enabled",
			h3: HTTP3Options{
				Authority:       config.DefaultEndpoint,
				EnableDatagrams: true,
			},
		},
		{
			name: "datagrams disabled",
			h3: HTTP3Options{
				Authority:       testkit.WarpIPv4Legacy443,
				EnableDatagrams: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := BuildConnectIPOptions(tt.h3)
			if options.Authority != defaultCloudflareConnectIPAuthority {
				t.Fatalf(errAuthorityMismatch, defaultCloudflareConnectIPAuthority, options.Authority)
			}
			if options.Protocol != ProtocolConnectIP {
				t.Fatalf(errProtocolMismatch, ProtocolConnectIP, options.Protocol)
			}
			if options.EnableDatagrams != tt.h3.EnableDatagrams {
				t.Fatalf("expected datagrams %v, got %v", tt.h3.EnableDatagrams, options.EnableDatagrams)
			}
		})
	}
}

// 验证 CONNECT-IP 会话参数会从连接参数中生成。
func TestBuildConnectIPOptions(t *testing.T) {
	options := BuildConnectIPOptions(HTTP3Options{
		Authority:       config.DefaultEndpoint,
		EnableDatagrams: true,
	})
	if options.Authority != defaultCloudflareConnectIPAuthority {
		t.Fatalf(errAuthorityMismatch, defaultCloudflareConnectIPAuthority, options.Authority)
	}
	if options.Protocol != ProtocolConnectIP {
		t.Fatalf(errProtocolMismatch, ProtocolConnectIP, options.Protocol)
	}
	if !options.EnableDatagrams {
		t.Fatal(errDatagramsEnabled)
	}
}

// 验证会话建立器会暴露最小状态快照。
func TestNewConnectIPSessionManager(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}
	snapshot := manager.Snapshot()
	if snapshot.State != SessionStateIdle {
		t.Fatalf("expected idle state, got %q", snapshot.State)
	}
	if snapshot.Protocol != ProtocolCFConnectIP {
		t.Fatalf(errProtocolMismatch, ProtocolCFConnectIP, snapshot.Protocol)
	}
}

// 验证 CONNECT-IP 会话管理器会暴露流量与时延统计入口。
func TestConnectIPSessionManagerStats(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}

	manager.RecordHandshakeLatency(85 * time.Millisecond)
	manager.AddTxBytes(64)
	manager.AddRxBytes(96)

	stats := manager.Stats()
	if stats.HandshakeLatency != 85*time.Millisecond {
		t.Fatalf("expected handshake latency 85ms, got %s", stats.HandshakeLatency)
	}
	if stats.TxBytes != 64 {
		t.Fatalf("expected tx bytes 64, got %d", stats.TxBytes)
	}
	if stats.RxBytes != 96 {
		t.Fatalf("expected rx bytes 96, got %d", stats.RxBytes)
	}
}

// 验证会话快照会复制路由切片，避免调用方修改内部状态。
func TestConnectIPSessionManagerSnapshotCopiesRoutes(t *testing.T) {
	manager, err := NewConnectIPSessionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf(errSessionManagerCreate, err)
	}

	info := SessionInfo{
		IPv4:   testkit.TunIPv4CIDR,
		Routes: []string{testkit.DefaultRouteV4, testkit.DefaultRouteV6},
	}
	manager.UpdateSessionInfo(info)

	snapshot := manager.Snapshot()
	info.Routes[0] = "mutated-source"
	snapshot.Routes[0] = "mutated-snapshot"

	again := manager.Snapshot()
	if again.Routes[0] != testkit.DefaultRouteV4 {
		t.Fatalf("expected copied routes in snapshot, got %+v", again.Routes)
	}
}

type countingTransportDialer struct {
	calls int
	conn  quicErrorCloser
	h3    h3ClientConn
	err   error
}

func (d *countingTransportDialer) Dial(ctx context.Context, quic QUICOptions, h3 HTTP3Options) (quicErrorCloser, h3ClientConn, time.Duration, error) {
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
		IPv4: testkit.TunIPv4CIDR,
		IPv6: testkit.TunIPv6CIDR,
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

// 验证 TUN 模式下核心 dialer 会在真实拨号前建立并复用 QUIC/H3 与 CONNECT-IP 会话。
func TestCoreTunnelDialerEnsuresCoreSessionOnce(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara0"},
	}

	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectionManagerCreate, err)
	}
	transportDialer := &countingTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}}
	connectionManager.dialer = transportDialer

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectIPManagerCreate, err)
	}
	connectDialer := &countingConnectIPDialer{session: &fakePacketSession{}}
	sessionManager.dialer = connectDialer

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	streamDialer := &stubHTTPStreamDialer{conn: clientConn}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf(errCoreTunnelDialerCreate, err)
	}
	dialer.provider = &fakePlatformProvider{platform: "linux", delegate: internaltun.NewFakeProvider()}
	dialer.adapter = internaltun.NewFakeAdapter()
	relayCalls := 0
	dialer.packetRelay = func(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
		relayCalls++
		<-ctx.Done()
		return context.Cause(ctx)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", quicExampleTCPAddress)
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	assertCoreTunnelDialerFirstSession(t, transportDialer, connectDialer, streamDialer, &relayCalls)

	if _, err := dialer.DialContext(context.Background(), "tcp", quicExampleTCPAddress); err != nil {
		t.Fatalf("expected second dial success, got %v", err)
	}
	assertCoreTunnelDialerReuse(t, transportDialer, connectDialer, streamDialer)
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
		HTTP:           config.HTTPConfig{ListenAddress: testkit.LocalListenZero},
	}

	connectionManager, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectionManagerCreate, err)
	}
	transportDialer := &countingTransportDialer{err: errors.New("quic unavailable")}
	connectionManager.dialer = transportDialer

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectIPManagerCreate, err)
	}
	streamDialer := &stubHTTPStreamDialer{}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf(errCoreTunnelDialerCreate, err)
	}
	dialer.provider = &fakePlatformProvider{platform: "linux", delegate: internaltun.NewFakeProvider()}
	dialer.adapter = internaltun.NewFakeAdapter()

	_, err = dialer.DialContext(context.Background(), "tcp", quicExampleTCPAddress)
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

// 验证 HTTP 代理模式不会强依赖 CONNECT-IP 会话，避免 2026 L4 Proxy Mode 被旧前置条件阻塞。
func TestCoreTunnelDialerHTTPModeDoesNotRequireConnectIP(t *testing.T) {
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
		t.Fatalf(errConnectionManagerCreate, err)
	}
	transportDialer := &countingTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}}
	connectionManager.dialer = transportDialer

	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf(errConnectIPManagerCreate, err)
	}
	connectDialer := &countingConnectIPDialer{err: errors.New("server didn't enable Extended CONNECT")}
	sessionManager.dialer = connectDialer

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	streamDialer := &stubHTTPStreamDialer{conn: clientConn}
	dialer, err := NewCoreTunnelDialer(connectionManager, sessionManager, streamDialer)
	if err != nil {
		t.Fatalf(errCoreTunnelDialerCreate, err)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", quicExampleTCPAddress)
	if err != nil {
		t.Fatalf("expected http mode dial success without connect-ip, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	if transportDialer.calls != 1 {
		t.Fatalf("expected one transport dial, got %d", transportDialer.calls)
	}
	if connectDialer.calls != 0 {
		t.Fatalf("expected connect-ip to be skipped in http mode, got %d calls", connectDialer.calls)
	}
	if streamDialer.calls != 1 {
		t.Fatalf("expected downstream dial once, got %d", streamDialer.calls)
	}
	if err := dialer.Close(); err != nil {
		t.Fatalf("expected core dialer close success, got %v", err)
	}
}

func TestCoreTunnelDialerHealthCheckRequiresPacketActivity(t *testing.T) {
	t.Parallel()

	var probeCalls atomic.Int32
	dialer := &CoreTunnelDialer{
		healthProbe: func(context.Context) error {
			probeCalls.Add(1)
			return nil
		},
		healthStats: func() packet.Snapshot {
			return packet.Snapshot{}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := dialer.HealthCheck(ctx)
	if err == nil {
		t.Fatal("expected tun health check failure without packet activity")
	}
	if probeCalls.Load() == 0 {
		t.Fatal("expected health probe to be called")
	}
}

func TestCoreTunnelDialerHealthCheckPassesWhenPacketActivityIncreases(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	dialer := &CoreTunnelDialer{
		healthProbe: func(context.Context) error {
			calls.Add(1)
			return nil
		},
		healthStats: func() packet.Snapshot {
			if calls.Load() == 0 {
				return packet.Snapshot{}
			}
			return packet.Snapshot{TxPackets: 1, TxBytes: 64}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := dialer.HealthCheck(ctx); err != nil {
		t.Fatalf("expected tun health check success, got %v", err)
	}
}

func TestPacketIORelayEmitsDiagnosticsAndStats(t *testing.T) {
	t.Parallel()

	logger := &capturingPacketLogger{}
	packetIO := NewPacketIO(1280)
	packetIO.SetLogger(logger)
	packetIO.traceLimit = 2

	dev := &stubRelayDevice{
		name: "igara-test0",
		mtu:  1280,
		inbound: [][]byte{
			ipv4Packet(quicTraceSourceAddress, testkit.PacketDstV4, 6, 64),
			ipv4Packet(quicTraceSourceAddress, testkit.PublicDNSV4, 17, 52),
		},
	}
	endpoint := &stubRelayEndpoint{
		downlink: [][]byte{
			ipv4Packet(testkit.PacketDstV4, quicTraceSourceAddress, 6, 112),
			ipv4Packet(testkit.PublicDNSV4, quicTraceSourceAddress, 17, 60),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	err := packetIO.Relay(ctx, dev, endpoint)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded from relay shutdown, got %v", err)
	}

	output := logger.String()
	for _, want := range []string{
		"packet relay started",
		"first uplink packet observed",
		"first downlink packet observed",
		"uplink packet #1",
		"uplink packet #2",
		"downlink packet #1",
		"downlink packet #2",
		"src=" + testkit.PacketSrcV4,
		"dst=" + testkit.PacketDstV4,
		"proto=tcp",
		"packet relay stopped",
		"rx_packets=2",
		"tx_packets=2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestPacketIOHelpersAndUtilityBranches(t *testing.T) {
	t.Parallel()

	packetIO := NewPacketIO(0)
	if packetIO.MTU() != 1280 {
		t.Fatalf("expected default mtu 1280, got %d", packetIO.MTU())
	}
	if stats := packetIO.Stats(); stats.RxPackets != 0 || stats.TxPackets != 0 {
		t.Fatalf("expected empty stats, got %+v", stats)
	}
	packetIO.logf("no logger attached")

	packetIO.traceLimit = 1
	logger := &capturingPacketLogger{}
	packetIO.SetLogger(logger)
	packetIO.tracePacket("uplink", 4, "igara0", []byte{0x45, 0x00, 0x00, 0x14})
	packetIO.tracePacket("uplink", 4, "igara0", []byte{0x45, 0x00, 0x00, 0x14})
	if strings.Count(logger.String(), "uplink packet #") != 1 {
		t.Fatalf("expected one traced uplink packet, got:\n%s", logger.String())
	}
}

func TestDatapathFormattingHelpers(t *testing.T) {
	assertPacketTraceLimitParsing(t)
	assertProtocolNameFormatting(t)
	assertPacketSummaryFormatting(t)
	assertPacketFragmentSplitting(t)
}

func assertCoreTunnelDialerFirstSession(t *testing.T, transportDialer *countingTransportDialer, connectDialer *countingConnectIPDialer, streamDialer *stubHTTPStreamDialer, relayCalls *int) {
	t.Helper()

	if transportDialer.calls != 1 {
		t.Fatalf("expected one transport dial, got %d", transportDialer.calls)
	}
	if connectDialer.calls != 1 {
		t.Fatalf("expected one connect-ip dial, got %d", connectDialer.calls)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && *relayCalls == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if *relayCalls != 1 {
		t.Fatalf("expected relay to start once, got %d", *relayCalls)
	}
	if streamDialer.calls != 1 {
		t.Fatalf("expected one downstream dial, got %d", streamDialer.calls)
	}
}

func assertCoreTunnelDialerReuse(t *testing.T, transportDialer *countingTransportDialer, connectDialer *countingConnectIPDialer, streamDialer *stubHTTPStreamDialer) {
	t.Helper()

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

func assertPacketTraceLimitParsing(t *testing.T) {
	t.Helper()

	t.Setenv(quicTracePacketsEnv, "")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected default trace limit 1, got %d", got)
	}
	t.Setenv(quicTracePacketsEnv, "3")
	if got := packetTraceLimitFromEnv(); got != 3 {
		t.Fatalf("expected trace limit 3, got %d", got)
	}
	t.Setenv(quicTracePacketsEnv, "bad")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected fallback trace limit 1, got %d", got)
	}
	t.Setenv(quicTracePacketsEnv, "-1")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected negative fallback trace limit 1, got %d", got)
	}
}

func assertProtocolNameFormatting(t *testing.T) {
	t.Helper()

	if got := ipProtocolName(1); got != "icmp" {
		t.Fatalf("unexpected icmp protocol name: %q", got)
	}
	if got := ipProtocolName(17); got != "udp" {
		t.Fatalf("unexpected udp protocol name: %q", got)
	}
	if got := ipProtocolName(250); got != "250" {
		t.Fatalf("unexpected unknown protocol name: %q", got)
	}
}

func assertPacketSummaryFormatting(t *testing.T) {
	t.Helper()

	if got := packetSummary(nil); got != "packet=empty" {
		t.Fatalf("unexpected empty packet summary: %q", got)
	}
	if got := packetSummary([]byte{0x45, 0x00}); got != "packet=ipv4_truncated" {
		t.Fatalf("unexpected truncated ipv4 summary: %q", got)
	}
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	ipv6[6] = 58
	copy(ipv6[8:24], netip.MustParseAddr(testkit.TestIPv6Doc).AsSlice())
	copy(ipv6[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	if got := packetSummary(ipv6); !strings.Contains(got, "version=6") || !strings.Contains(got, "icmpv6") {
		t.Fatalf("unexpected ipv6 summary: %q", got)
	}
	if got := packetSummary([]byte{0x10}); !strings.Contains(got, "unknown_version") {
		t.Fatalf("unexpected unknown version summary: %q", got)
	}
}

func assertPacketFragmentSplitting(t *testing.T) {
	t.Helper()

	fragments := splitPacketByMTU([]byte{1, 2, 3, 4, 5}, 2)
	if len(fragments) != 3 || len(fragments[2]) != 1 {
		t.Fatalf("unexpected fragments: %+v", fragments)
	}
	if got := splitPacketByMTU([]byte{1, 2}, 0); len(got) != 1 {
		t.Fatalf("expected single fragment when mtu<=0, got %+v", got)
	}
	if got := splitPacketByMTU(nil, 2); got != nil {
		t.Fatalf("expected nil fragments for empty payload, got %+v", got)
	}
}

func TestNormalizeRelayReadErrorBranches(t *testing.T) {
	t.Parallel()

	if idle, err := normalizeRelayReadError(context.Background(), nil); idle || err != nil {
		t.Fatalf("expected non-idle nil error, got idle=%v err=%v", idle, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if idle, err := normalizeRelayReadError(ctx, io.EOF); !idle || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled idle error, got idle=%v err=%v", idle, err)
	}

	if idle, err := normalizeRelayReadError(context.Background(), io.EOF); !idle || err != nil {
		t.Fatalf("expected idle EOF normalization, got idle=%v err=%v", idle, err)
	}

	if idle, err := normalizeRelayReadError(context.Background(), errors.New("boom")); idle || err != nil {
		t.Fatalf("expected non-idle generic error, got idle=%v err=%v", idle, err)
	}
}

type capturingPacketLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *capturingPacketLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *capturingPacketLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type stubRelayDevice struct {
	name    string
	mtu     int
	inbound [][]byte
	written [][]byte
}

func (d *stubRelayDevice) Name() string { return d.name }
func (d *stubRelayDevice) MTU() int     { return d.mtu }
func (d *stubRelayDevice) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if len(d.inbound) == 0 {
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		default:
			return 0, io.EOF
		}
	}
	packet := d.inbound[0]
	d.inbound = d.inbound[1:]
	return copy(dst, packet), nil
}
func (d *stubRelayDevice) WritePacket(_ context.Context, packet []byte) (int, error) {
	d.written = append(d.written, append([]byte(nil), packet...))
	return len(packet), nil
}
func (d *stubRelayDevice) Close() error { return nil }

type stubRelayEndpoint struct {
	downlink [][]byte
}

func (e *stubRelayEndpoint) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if len(e.downlink) == 0 {
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		default:
			return 0, io.EOF
		}
	}
	packet := e.downlink[0]
	e.downlink = e.downlink[1:]
	return copy(dst, packet), nil
}
func (e *stubRelayEndpoint) WritePacket(_ context.Context, packet []byte) ([]byte, error) {
	return nil, nil
}
func (e *stubRelayEndpoint) Close() error { return nil }

func ipv4Packet(src, dst string, proto byte, totalLen int) []byte {
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], mustIPv4Bytes(src))
	copy(packet[16:20], mustIPv4Bytes(dst))
	return packet
}

func mustIPv4Bytes(text string) []byte {
	var a, b, c, d byte
	_, _ = fmt.Sscanf(text, "%d.%d.%d.%d", &a, &b, &c, &d)
	return []byte{a, b, c, d}
}

// 验证 TLS 配置会装配客户端证书材料。
func TestBuildTLSConfigIncludesClientCertificate(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		ServerName:        config.DefaultSNI,
		ClientPrivateKey:  testClientPrivateKeyBase64,
		ClientCertificate: testClientCertificateBase64,
	})
	if tlsCfg.ServerName != config.DefaultSNI {
		t.Fatalf(errServerNameMismatch, config.DefaultSNI, tlsCfg.ServerName)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected one client certificate, got %d", len(tlsCfg.Certificates))
	}
	if _, ok := tlsCfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatal("expected parsed client private key in tls certificate")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("expected tls config to keep certificate verification enabled")
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("expected tls config to carry a root CA pool")
	}
}

// 验证无效证书材料不会污染 TLS 配置。
func TestBuildTLSConfigSkipsInvalidClientCertificate(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		ServerName:        config.DefaultSNI,
		ClientPrivateKey:  "invalid",
		ClientCertificate: "invalid",
	})
	if len(tlsCfg.Certificates) != 0 {
		t.Fatalf("expected no client certificate on invalid materials, got %d", len(tlsCfg.Certificates))
	}
}

func TestBuildTLSConfigUsesDefaultSNIWhenUnset(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{})
	if tlsCfg.ServerName != config.DefaultSNI {
		t.Fatalf("expected default server name %q, got %q", config.DefaultSNI, tlsCfg.ServerName)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("expected default tls config to verify peer certificates")
	}
}

func TestBuildTLSConfigUsesPinnedMASQUEVerificationForAltPorts(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		Endpoint:          testkit.WarpIPv4Alt500,
		ServerName:        config.DefaultSNI,
		PeerPublicKey:     testMASQUEPeerPublicKeyPEM,
		ClientPrivateKey:  testClientPrivateKeyBase64,
		ClientCertificate: testClientCertificateBase64,
	})
	if tlsCfg.ServerName != quicMasqueServerName {
		t.Fatalf("expected MASQUE server name, got %q", tlsCfg.ServerName)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Fatal("expected pinned MASQUE mode to enable custom verification path")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("expected pinned MASQUE verifier")
	}
}

func TestPinnedMASQUEVerifierAcceptsMatchingLeaf(t *testing.T) {
	verifier := buildPinnedMASQUEVerifier(quicMasqueServerName, testMASQUEPeerPublicKeyPEM)
	raw, err := base64.StdEncoding.DecodeString(testMASQUELeafCertBase64)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if err := verifier([][]byte{raw}, nil); err != nil {
		t.Fatalf("expected verifier success, got %v", err)
	}
}

func TestPinnedMASQUEVerifierRejectsWrongPinnedKey(t *testing.T) {
	verifier := buildPinnedMASQUEVerifier(quicMasqueServerName, testOtherPublicKeyPEM)
	raw, err := base64.StdEncoding.DecodeString(testMASQUELeafCertBase64)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if err := verifier([][]byte{raw}, nil); err == nil {
		t.Fatal("expected verifier failure for mismatched pinned key")
	}
}

var _ tls.Certificate

const (
	testClientPrivateKeyBase64  = "MHcCAQEEIP2wC9ZwTe74MkRUYw35vj0IadB1iKsFcfoTmyaKOAqvoAoGCCqGSM49AwEHoUQDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw=="
	testClientCertificateBase64 = "MIIBCDCBr6ADAgECAgEAMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMTCWlnYXJhLXRlc3QwHhcNMjYwMzI0MDAwMDAwWhcNMjYwMzI1MDAwMDAwWjAUMRIwEAYDVQQDEwlpZ2FyYS10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzm6MSMBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0kAMEYCIQDYPe0nLBKBPXn1HULICwhf66A1VpzwuNFuIBqmoeZa9QIhAJ6xPD58Ll35H5TADaBrZEcD3xKhsR4HIX66vepQP9en"
	testMASQUELeafCertBase64    = "MIICPzCCAcWgAwIBAgIUc2dOs+UVA8fE6UO4F/QWdHT8JoEwCgYIKoZIzj0EAwMwTjELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEENsb3VkZmxhcmUsIEluYy4xJDAiBgNVBAMMGzIwMjQtMDItMjcgU2VsZi1TaWduZWQgUm9vdDAeFw0yNjAxMjYxMDQ1MDZaFw0yNzAyMjYxMDQ1MDZaMCYxJDAiBgNVBAMMG21hc3F1ZS5jbG91ZGZsYXJlY2xpZW50LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCGlOzE6CZvTSqfGHxsUeq/v4eJnBu0sSPLbFvDkdQObb/8ws1WwkUYdrfO/5MZz+pQMtJZK+6mMLvqMfpN3a+ujgagwgaUwHQYDVR0OBBYEFMv1d+q9sqfM3gXICqoYHSa7GKJMMB8GA1UdIwQYMBaAFFDWHnoISkfPE/lnoezNAkLPEhxwMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAmBgNVHREEHzAdghttYXNxdWUuY2xvdWRmbGFyZWNsaWVudC5jb20wCgYIKoZIzj0EAwMDaAAwZQIwLS/QI/GHtOvBaf5jYJJtCUrDOITNY0hl7RZMcye4txaJaC2xEs9Nbo673Mku5QLUAjEAlzppJWKclkTTZLoIBRdbyIZnf0nKnGKEoA0kRh6eChPf2n6csMhL1VOVAz1EMgOu"
	testMASQUEPeerPublicKeyPEM  = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----"
	testOtherPublicKeyPEM       = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3\na1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw==\n-----END PUBLIC KEY-----"
)
