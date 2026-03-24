package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

type stubUDPAssociateRelay struct {
	requests []UDPAssociateRequest
	response UDPAssociateResponse
	err      error
}

func (s *stubUDPAssociateRelay) Exchange(_ context.Context, req UDPAssociateRequest) (UDPAssociateResponse, error) {
	s.requests = append(s.requests, req)
	if s.err != nil {
		return UDPAssociateResponse{}, s.err
	}
	return s.response, nil
}

type stubStreamDialer struct {
	open func(context.Context, ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error)
}

func (d stubStreamDialer) DialStream(ctx context.Context, _ h3ClientConn, _ QUICOptions, _ HTTP3Options, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
	return d.open(ctx, opts)
}

type trackedConn struct {
	net.Conn
	closeCount atomic.Int32
	closeCh    chan struct{}
	closeOnce  sync.Once
}

func newTrackedConn(conn net.Conn) *trackedConn {
	return &trackedConn{Conn: conn, closeCh: make(chan struct{})}
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	if c.closeCount.Add(1) == 1 {
		c.closeOnce.Do(func() { close(c.closeCh) })
	}
	return err
}

func (c *trackedConn) Closed() <-chan struct{} {
	return c.closeCh
}

// 验证 SOCKS5 会执行用户名密码握手并建立 UDP associate 数据面。
func TestSOCKSManagerUserPassAndUDPAssociate(t *testing.T) {
	mgr, err := NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
			Username:      "demo",
			Password:      "secret",
			EnableUDP:     true,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	relay := &stubUDPAssociateRelay{
		response: UDPAssociateResponse{
			SourceAddress: "1.1.1.1:53",
			Payload:       []byte("pong"),
		},
	}
	mgr.SetUDPAssociateRelay(relay)
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := mgr.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, err := net.Dial("tcp", mgr.ListenAddress())
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("expected method negotiation write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected method negotiation read success, got %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("unexpected method negotiation reply %v", reply)
	}

	auth := []byte{0x01, 0x04, 'd', 'e', 'm', 'o', 0x06, 's', 'e', 'c', 'r', 'e', 't'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("expected auth write success, got %v", err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected auth reply read success, got %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("expected auth success, got %v", reply)
	}

	associateReq := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(associateReq); err != nil {
		t.Fatalf("expected udp associate request write success, got %v", err)
	}
	udpReply, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatalf("expected udp associate reply success, got %v", err)
	}
	if udpReply.reply != 0x00 {
		t.Fatalf("expected udp associate success, got %#x", udpReply.reply)
	}

	udpConn, err := net.Dial("udp", udpReply.boundAddress)
	if err != nil {
		t.Fatalf("expected udp relay dial success, got %v", err)
	}
	defer udpConn.Close()

	packet := buildUDPAssociatePacket(t, "1.1.1.1:53", []byte("ping"))
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatalf("expected udp packet write success, got %v", err)
	}

	_ = udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatalf("expected udp response read success, got %v", err)
	}
	target, payload := parseUDPAssociatePacket(t, buf[:n])
	if target != "1.1.1.1:53" {
		t.Fatalf("expected response source 1.1.1.1:53, got %q", target)
	}
	if string(payload) != "pong" {
		t.Fatalf("expected payload pong, got %q", payload)
	}

	if len(relay.requests) != 1 {
		t.Fatalf("expected one relay request, got %d", len(relay.requests))
	}
	if relay.requests[0].TargetAddress != "1.1.1.1:53" {
		t.Fatalf("expected target 1.1.1.1:53, got %q", relay.requests[0].TargetAddress)
	}
	if string(relay.requests[0].Payload) != "ping" {
		t.Fatalf("expected payload ping, got %q", relay.requests[0].Payload)
	}

	stats := mgr.Stats()
	if stats.TxBytes != 4 || stats.RxBytes != 4 {
		t.Fatalf("expected tx/rx bytes 4/4, got %+v", stats)
	}
	if stats.HandshakeLatency <= 0 {
		t.Fatalf("expected positive handshake latency, got %+v", stats)
	}
}

// 验证认证失败时服务端会返回 RFC1929 失败响应。
func TestSOCKSManagerRejectsInvalidUserPass(t *testing.T) {
	mgr, err := NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
			Username:      "demo",
			Password:      "secret",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := mgr.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn, err := net.Dial("tcp", mgr.ListenAddress())
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("expected method negotiation write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected method negotiation read success, got %v", err)
	}
	if reply[1] != 0x02 {
		t.Fatalf("expected userpass auth selection, got %v", reply)
	}

	auth := []byte{0x01, 0x04, 'd', 'e', 'm', 'o', 0x05, 'w', 'r', 'o', 'n', 'g'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("expected auth write success, got %v", err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected auth reply read success, got %v", err)
	}
	if reply[1] != 0x01 {
		t.Fatalf("expected auth failure, got %v", reply)
	}
}

func TestSOCKSManagerConnectRelaysBytesAndClosesBothSides(t *testing.T) {
	var tracked *trackedConn
	streamMgr := newTestConnectStreamManager(t, func(_ context.Context, opts ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		if opts.TargetHost != "example.com" || opts.TargetPort != "443" {
			t.Fatalf("unexpected target %+v", opts)
		}
		clientSide, upstreamSide := net.Pipe()
		tracked = newTrackedConn(clientSide)
		go func() {
			defer upstreamSide.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(upstreamSide, buf); err != nil {
				return
			}
			if string(buf) != "ping" {
				t.Errorf("expected upstream payload ping, got %q", string(buf))
				return
			}
			if _, err := upstreamSide.Write([]byte("pong")); err != nil {
				t.Errorf("expected upstream write success, got %v", err)
				return
			}
		}()
		return tracked, nil, 5 * time.Millisecond, nil
	})

	mgr, err := NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	mgr.SetStreamManager(streamMgr)
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := mgr.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn := dialSOCKSClient(t, mgr.ListenAddress())
	defer conn.Close()
	negotiateSOCKSNoAuth(t, conn)
	sendSOCKSConnectRequest(t, conn, "example.com", 443)

	reply, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatalf("expected connect reply success, got %v", err)
	}
	if reply.reply != socksReplySucceeded {
		t.Fatalf("expected connect success, got %#x", reply.reply)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected tunneled write success, got %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("expected tunneled read success, got %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("expected tunneled payload pong, got %q", string(buf))
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected client EOF after upstream close, got %v", err)
	}

	waitForSOCKSCondition(t, 2*time.Second, func() bool {
		if tracked == nil {
			return false
		}
		select {
		case <-tracked.Closed():
			return true
		default:
			return false
		}
	}, "expected upstream stream conn closed")

	waitForSOCKSCondition(t, 2*time.Second, func() bool {
		return streamMgr.StreamEndpoint("example.com", "443") == nil
	}, "expected closed stream removed from manager")

	stats := waitForSOCKSStats(t, mgr, func(s types.Stats) bool {
		return s.TxBytes >= 4 && s.RxBytes >= 4
	})
	if stats.TxBytes < 4 || stats.RxBytes < 4 {
		t.Fatalf("expected connect transfer stats, got %+v", stats)
	}
	if stats.HandshakeLatency <= 0 {
		t.Fatalf("expected handshake latency recorded, got %+v", stats)
	}
	if streamMgr.Stats().HandshakeLatency <= 0 {
		t.Fatalf("expected stream manager handshake latency recorded, got %+v", streamMgr.Stats())
	}
}

func TestSOCKSManagerConnectFailureReturnsGeneralFailure(t *testing.T) {
	streamMgr := newTestConnectStreamManager(t, func(context.Context, ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error) {
		return nil, nil, 0, errors.New("open stream failed")
	})

	mgr, err := NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	mgr.SetStreamManager(streamMgr)
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	defer func() {
		if err := mgr.Stop(context.Background()); err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	}()

	conn := dialSOCKSClient(t, mgr.ListenAddress())
	defer conn.Close()
	negotiateSOCKSNoAuth(t, conn)
	sendSOCKSConnectRequest(t, conn, "example.com", 443)

	reply, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatalf("expected connect failure reply success, got %v", err)
	}
	if reply.reply != socksReplyGeneralFailure {
		t.Fatalf("expected general failure reply, got %#x", reply.reply)
	}
}

func newTestConnectStreamManager(t *testing.T, open func(context.Context, ConnectStreamOptions) (net.Conn, *http.Response, time.Duration, error)) *ConnectStreamManager {
	t.Helper()
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
	}
	cfg.FillDefaults()
	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("expected connect stream manager creation success, got %v", err)
	}
	mgr.dialer = stubStreamDialer{open: open}
	mgr.SetReady()
	return mgr
}

func dialSOCKSClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("expected dial success, got %v", err)
	}
	return conn
}

func negotiateSOCKSNoAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("expected method negotiation write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected method negotiation read success, got %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected method negotiation reply %v", reply)
	}
}

func sendSOCKSConnectRequest(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, []byte(host)...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
}

func waitForSOCKSStats(t *testing.T, manager *SOCKSManager, fn func(types.Stats) bool) types.Stats {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats := manager.Stats()
		if fn(stats) {
			return stats
		}
		time.Sleep(10 * time.Millisecond)
	}
	return manager.Stats()
}

func waitForSOCKSCondition(t *testing.T, timeout time.Duration, fn func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

func buildUDPAssociatePacket(t *testing.T, address string, payload []byte) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("expected valid address, got %v", err)
	}
	portValue, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("expected valid port, got %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatal("expected ipv4 address")
	}
	packet := []byte{0x00, 0x00, 0x00, 0x01}
	packet = append(packet, ip...)
	packet = append(packet, byte(portValue>>8), byte(portValue))
	packet = append(packet, payload...)
	return packet
}

func parseUDPAssociatePacket(t *testing.T, packet []byte) (string, []byte) {
	t.Helper()
	if len(packet) < 10 {
		t.Fatalf("expected valid packet, got %v", packet)
	}
	host := net.IP(packet[4:8]).String()
	port := int(binary.BigEndian.Uint16(packet[8:10]))
	return net.JoinHostPort(host, strconv.Itoa(port)), append([]byte(nil), packet[10:]...)
}

type socksReply struct {
	reply        byte
	boundAddress string
}

func readSOCKSReply(r io.Reader) (socksReply, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return socksReply{}, err
	}
	if header[3] != 0x01 {
		return socksReply{}, errors.New("expected ipv4 bind address")
	}
	addr := make([]byte, 4)
	if _, err := io.ReadFull(r, addr); err != nil {
		return socksReply{}, err
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return socksReply{}, err
	}
	return socksReply{
		reply:        header[1],
		boundAddress: net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(int(binary.BigEndian.Uint16(port)))),
	}, nil
}
