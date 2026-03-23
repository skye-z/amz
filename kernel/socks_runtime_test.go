package kernel_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

type stubUDPAssociateRelay struct {
	requests []kernel.UDPAssociateRequest
	response kernel.UDPAssociateResponse
	err      error
}

func (s *stubUDPAssociateRelay) Exchange(_ context.Context, req kernel.UDPAssociateRequest) (kernel.UDPAssociateResponse, error) {
	s.requests = append(s.requests, req)
	if s.err != nil {
		return kernel.UDPAssociateResponse{}, s.err
	}
	return s.response, nil
}

// 验证 SOCKS5 会执行用户名密码握手并建立 UDP associate 数据面。
func TestSOCKSManagerUserPassAndUDPAssociate(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
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
		response: kernel.UDPAssociateResponse{
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
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
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
