package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
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
	t.Setenv("AMZ_TUN_TRACE_PACKETS", "")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected default trace limit 1, got %d", got)
	}
	t.Setenv("AMZ_TUN_TRACE_PACKETS", "3")
	if got := packetTraceLimitFromEnv(); got != 3 {
		t.Fatalf("expected trace limit 3, got %d", got)
	}
	t.Setenv("AMZ_TUN_TRACE_PACKETS", "bad")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected fallback trace limit 1, got %d", got)
	}
	t.Setenv("AMZ_TUN_TRACE_PACKETS", "-1")
	if got := packetTraceLimitFromEnv(); got != 1 {
		t.Fatalf("expected negative fallback trace limit 1, got %d", got)
	}

	if got := ipProtocolName(1); got != "icmp" {
		t.Fatalf("unexpected icmp protocol name: %q", got)
	}
	if got := ipProtocolName(17); got != "udp" {
		t.Fatalf("unexpected udp protocol name: %q", got)
	}
	if got := ipProtocolName(250); got != "250" {
		t.Fatalf("unexpected unknown protocol name: %q", got)
	}

	if got := packetSummary(nil); got != "packet=empty" {
		t.Fatalf("unexpected empty packet summary: %q", got)
	}
	if got := packetSummary([]byte{0x45, 0x00}); got != "packet=ipv4_truncated" {
		t.Fatalf("unexpected truncated ipv4 summary: %q", got)
	}
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	ipv6[6] = 58
	copy(ipv6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(ipv6[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	if got := packetSummary(ipv6); !strings.Contains(got, "version=6") || !strings.Contains(got, "icmpv6") {
		t.Fatalf("unexpected ipv6 summary: %q", got)
	}
	if got := packetSummary([]byte{0x10}); !strings.Contains(got, "unknown_version") {
		t.Fatalf("unexpected unknown version summary: %q", got)
	}

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
