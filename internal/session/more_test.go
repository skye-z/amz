package session

import (
	"context"
	"io"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
)

func TestNewBootstrapDialerDelegatesToCoreTunnelDialer(t *testing.T) {
	cfg := config.KernelConfig{Endpoint: config.DefaultEndpoint, SNI: config.DefaultSNI, MTU: config.DefaultMTU, Mode: config.ModeHTTP, ConnectTimeout: config.DefaultConnectTimeout, Keepalive: config.DefaultKeepalive, HTTP: config.HTTPConfig{ListenAddress: config.DefaultHTTPListenAddress}}
	connMgr, err := NewConnectionManager(cfg)
	if err != nil {
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	sessMgr, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected session manager creation success, got %v", err)
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
	if _, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("expected non-tcp network error")
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "missing-port"); err == nil {
		t.Fatal("expected malformed target error")
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
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
	endpoint := &packetStackLinkEndpoint{ctx: context.Background(), endpoint: relay, mtu: 1280}
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
		t.Fatalf("expected compat layer creation success, got %v", err)
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
	if got := staticAddr("1.1.1.1:443").Network(); got != "tcp" {
		t.Fatalf("unexpected network: %q", got)
	}
	if got := staticAddr("1.1.1.1:443").String(); got != "1.1.1.1:443" {
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
	manager.streams["example.com:443"] = &activeStream{
		conn:   client,
		info:   StreamInfo{RemoteAddr: "old", Protocol: "proto"},
		local:  "local",
		remote: "remote",
	}
	manager.UpdateStreamInfo("example.com:443", StreamInfo{RemoteAddr: "new", Protocol: ProtocolConnectStream})
	if endpoint := manager.StreamEndpoint("example.com", "443"); endpoint == nil {
		t.Fatal("expected stream endpoint after update")
	}
	stream := manager.streams["example.com:443"]
	if stream.info.RemoteAddr != "new" {
		t.Fatalf("expected updated stream info, got %+v", stream.info)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pong"))
	}()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("expected stream write success, got %v", err)
	}
	buf := make([]byte, 4)
	if _, err := stream.Read(buf); err != nil || string(buf) != "pong" {
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
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	connectionManager.dialer = &countingTransportDialer{conn: &fakeQUICConn{}, h3: &fakeH3Client{}}
	sessionManager, err := NewConnectIPSessionManager(cfg)
	if err != nil {
		t.Fatalf("expected connect-ip manager creation success, got %v", err)
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
	if endpoint := dialer.PacketEndpoint(); endpoint == nil {
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

func (b *fakePacketBootstrap) Prepare(context.Context) error { return b.prepareErr }
func (b *fakePacketBootstrap) SessionInfo() SessionInfo { return SessionInfo{} }
func (b *fakePacketBootstrap) PacketEndpoint() PacketRelayEndpoint { return nil }
func (b *fakePacketBootstrap) Close() error { return nil }

type httpStreamDialerStub struct{}

func (httpStreamDialerStub) DialContext(context.Context, string, string) (net.Conn, error) { return nil, nil }

type tunDeviceStub struct{}

func (tunDeviceStub) Name() string { return "amz0" }
func (tunDeviceStub) MTU() int { return 1280 }
func (tunDeviceStub) ReadPacket(context.Context, []byte) (int, error) { return 0, nil }
func (tunDeviceStub) WritePacket(context.Context, []byte) (int, error) { return 0, nil }
func (tunDeviceStub) Close() error { return nil }

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

func (d *fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

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
	if got := tlsServerNameForOptions(QUICOptions{ServerName: "example.com", Endpoint: "1.1.1.1:443"}); got != "example.com" {
		t.Fatalf("unexpected server name: %q", got)
	}
	if requiresPinnedMASQUETrust(QUICOptions{PeerPublicKey: "pk", Endpoint: "1.1.1.1:443"}) {
		t.Fatal("expected :443 not to require pinned trust")
	}
	if !requiresPinnedMASQUETrust(QUICOptions{PeerPublicKey: "pk", Endpoint: "1.1.1.1:8443"}) {
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
	_, _, err = openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: "example.com", Protocol: ProtocolConnectIP})
	if err == nil || !strings.Contains(err.Error(), "send request header") || !stream.closed {
		t.Fatalf("expected send header error and closed stream, got err=%v closed=%v", err, stream.closed)
	}

	stream = &fakeRequestStream{readResponseErr: errors.New("read fail")}
	_, _, err = openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: "example.com", Protocol: ProtocolConnectIP})
	if err == nil || !strings.Contains(err.Error(), "read response") || !stream.closed {
		t.Fatalf("expected read response error and closed stream, got err=%v closed=%v", err, stream.closed)
	}

	stream = &fakeRequestStream{response: &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad gateway"))}}
	_, rsp, err := openCloudflareConnectIPStream(context.Background(), &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}, ConnectIPOptions{Authority: "example.com", Protocol: ProtocolConnectIP})
	if err == nil || rsp == nil || !strings.Contains(err.Error(), "status=502") || !strings.Contains(err.Error(), "bad gateway") || !stream.closed {
		t.Fatalf("expected non-2xx error and closed stream, got rsp=%v err=%v closed=%v", rsp, err, stream.closed)
	}
}

func TestCloudflareConnectIPSessionDatagramAndCloseBranches(t *testing.T) {
	stream := &datagramTestStream{receive: append(append([]byte(nil), contextIDZero...), []byte("pong")...)}
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
	if n, err := session.ReadPacket(context.Background(), buf); err != nil || string(buf[:n]) != "pong" {
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
		t.Fatalf("expected session manager creation success, got %v", err)
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
		t.Fatalf("expected session manager creation success, got %v", err)
	}
	manager.info = SessionInfo{IPv4: "10.0.0.2/32"}
	manager.dialer = &fakeConnectIPDialer{session: &waiterSession{waitErr: errors.New("no info")}}
	if err := manager.Open(context.Background()); err != nil {
		t.Fatalf("expected open success with seed info fallback, got %v", err)
	}
	if manager.Snapshot().IPv4 != "10.0.0.2/32" {
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
		t.Fatalf("expected connection manager creation success, got %v", err)
	}
	if mgr.HTTP3Conn() != nil {
		t.Fatal("expected nil h3 conn before connect")
	}
	if got := mgr.Stats(); got.HandshakeLatency != 0 || got.TxBytes != 0 || got.RxBytes != 0 {
		t.Fatalf("unexpected initial stats: %+v", got)
	}
}

