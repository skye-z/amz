package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPacketIORelayEmitsDiagnosticsAndStats(t *testing.T) {
	t.Parallel()

	logger := &capturingPacketLogger{}
	packetIO := NewPacketIO(1280)
	packetIO.SetLogger(logger)
	packetIO.traceLimit = 2

	dev := &stubRelayDevice{
		name:    "igara-test0",
		mtu:     1280,
		inbound: [][]byte{
			ipv4Packet("10.0.0.8", "104.28.152.116", 6, 64),
			ipv4Packet("10.0.0.8", "1.1.1.1", 17, 52),
		},
	}
	endpoint := &stubRelayEndpoint{
		downlink: [][]byte{
			ipv4Packet("104.28.152.116", "10.0.0.8", 6, 112),
			ipv4Packet("1.1.1.1", "10.0.0.8", 17, 60),
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
		"src=10.0.0.8",
		"dst=104.28.152.116",
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
