package runtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
)

func TestEncodeSOCKSAddressSupportsIPv4DomainAndIPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		atyp    byte
		check   func(*testing.T, []byte)
	}{
		{
			name:    "ipv4",
			address: "1.2.3.4:53",
			atyp:    socksAtypIPv4,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:5]).String(); got != "1.2.3.4" {
					t.Fatalf("expected ipv4 host 1.2.3.4, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[5:7])); got != 53 {
					t.Fatalf("expected ipv4 port 53, got %d", got)
				}
			},
		},
		{
			name:    "domain",
			address: "example.com:443",
			atyp:    socksAtypDomain,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				hostLen := int(encoded[1])
				if got := string(encoded[2 : 2+hostLen]); got != "example.com" {
					t.Fatalf("expected domain host example.com, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[2+hostLen:])); got != 443 {
					t.Fatalf("expected domain port 443, got %d", got)
				}
			},
		},
		{
			name:    "ipv6",
			address: "[2001:db8::1]:8443",
			atyp:    socksAtypIPv6,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:17]).String(); got != "2001:db8::1" {
					t.Fatalf("expected ipv6 host 2001:db8::1, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[17:19])); got != 8443 {
					t.Fatalf("expected ipv6 port 8443, got %d", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := encodeSOCKSAddress(tt.address)
			if err != nil {
				t.Fatalf("expected encode success, got %v", err)
			}
			if encoded[0] != tt.atyp {
				t.Fatalf("expected atyp %#x, got %#x", tt.atyp, encoded[0])
			}
			tt.check(t, encoded)
		})
	}
}

func TestBuildAndParseSOCKSUDPDatagramRoundTrip(t *testing.T) {
	t.Parallel()

	address := "8.8.8.8:53"
	payload := []byte("dns-query")

	packet, err := buildSOCKSUDPDatagram(address, payload)
	if err != nil {
		t.Fatalf("expected build success, got %v", err)
	}
	if !bytes.Equal(packet[:3], []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("expected reserved header prefix, got %v", packet[:3])
	}

	target, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if target != address {
		t.Fatalf("expected target %q, got %q", address, target)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("expected payload %q, got %q", string(payload), string(gotPayload))
	}
}

func TestEncodeSOCKSAddressRejectsOutOfRangePorts(t *testing.T) {
	t.Parallel()

	tests := []string{
		"1.2.3.4:-1",
		"1.2.3.4:65536",
		"example.com:70000",
	}

	for _, address := range tests {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			if _, err := encodeSOCKSAddress(address); err == nil {
				t.Fatalf("expected out-of-range port error for %q", address)
			}
		})
	}
}

func TestSOCKS5ManagerStopClosesActiveTCPConnections(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected auth reply success, got %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- manager.Stop(context.Background())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected stop success, got %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		_ = conn.Close()
		err := <-done
		if err != nil {
			t.Fatalf("expected stop success after unblock, got %v", err)
		}
		t.Fatal("expected Stop to return promptly without waiting for client-side close")
	}
}

func TestSOCKS5ManagerReportsFailureWhenUpstreamDialFails(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.SetDialer(&failingContextDialer{err: io.EOF})
	var reported atomic.Bool
	manager.SetFailureReporter(func(failure.Event) {
		reported.Store(true)
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected greeting read success, got %v", err)
	}
	connectRequest := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}, []byte("example.com")...)
	connectRequest = append(connectRequest, 0x01, 0xbb)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadAtLeast(conn, resp, 2); err != nil {
		t.Fatalf("expected connect response, got %v", err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && !reported.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !reported.Load() {
		t.Fatal("expected upstream dial failure to be reported")
	}
}

func TestSOCKS5ManagerRetriesCurrentConnectAfterFailureReporterSwapsBackend(t *testing.T) {
	t.Parallel()

	manager, err := NewSOCKS5Manager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS:          config.SOCKSConfig{ListenAddress: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.SetDialer(&failingContextDialer{err: context.DeadlineExceeded})
	manager.SetFailureReporter(func(failure.Event) {
		manager.SetDialer(echoHTTPDialer{})
	})

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected manager start success, got %v", err)
	}
	defer manager.Close()

	conn, err := net.Dial("tcp", manager.ListenAddress())
	if err != nil {
		t.Fatalf("expected socks dial success, got %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatalf("expected greeting write success, got %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected greeting read success, got %v", err)
	}
	connectRequest := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}, []byte("example.com")...)
	connectRequest = append(connectRequest, 0x01, 0xbb)
	if _, err := conn.Write(connectRequest); err != nil {
		t.Fatalf("expected connect request write success, got %v", err)
	}
	resp, err := io.ReadAll(io.LimitReader(conn, 10))
	if err != nil {
		t.Fatalf("expected connect response success, got %v", err)
	}
	if len(resp) < 2 || resp[1] != socksReplySucceeded {
		t.Fatalf("expected socks success reply after retry, got %v", resp)
	}
}

type failingContextDialer struct {
	err error
}

func (d *failingContextDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}
