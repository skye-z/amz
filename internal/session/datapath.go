package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/packet"
)

const (
	packetIdleBackoff           = 5 * time.Millisecond
	maxPacketBufferSize         = 65535
	errPacketIOTUNRequired      = "%w: tun device is required"
	errPacketIOEndpointRequired = "%w: packet relay endpoint is required"
)

// 约定隧道远端最小数据面收发接口。
type PacketRelayEndpoint interface {
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) ([]byte, error)
	Close() error
}

// 描述数据面的最小包收发骨架。
type PacketIO struct {
	mtu    int
	pool   *packet.BufferPool
	stats  *packet.Stats
	logger config.Logger

	traceLimit        int
	uplinkTraceSeen   int
	downlinkTraceSeen int
}

// 创建带缓冲池和统计的最小数据面对象。
func NewPacketIO(mtu int) *PacketIO {
	if mtu <= 0 {
		mtu = config.DefaultMTU
	}
	return &PacketIO{
		mtu:        mtu,
		pool:       packet.NewBufferPool(maxPacketBufferSize),
		stats:      packet.NewStats(),
		traceLimit: packetTraceLimitFromEnv(),
	}
}

// 返回当前数据面使用的 MTU。
func (p *PacketIO) MTU() int {
	return p.mtu
}

// 返回当前数据面的最小统计信息。
func (p *PacketIO) Stats() packet.Snapshot {
	return p.stats.Snapshot()
}

func (p *PacketIO) SetLogger(logger config.Logger) {
	p.logger = logger
}

// Relay 启动双向收发循环，并在上下文结束时关闭远端数据面。
func (p *PacketIO) Relay(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
	if dev == nil {
		return fmt.Errorf(errPacketIOTUNRequired, config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf(errPacketIOEndpointRequired, config.ErrInvalidConfig)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	defer func() { _ = endpoint.Close() }()
	p.logf("packet relay started device=%q mtu=%d", dev.Name(), p.mtu)
	defer func() {
		stats := p.stats.Snapshot()
		p.logf("packet relay stopped rx_packets=%d tx_packets=%d rx_bytes=%d tx_bytes=%d", stats.RxPackets, stats.TxPackets, stats.RxBytes, stats.TxBytes)
	}()

	go func() {
		<-ctx.Done()
		_ = endpoint.Close()
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- p.ForwardUplink(ctx, dev, endpoint) }()
	go func() { errCh <- p.ForwardDownlink(ctx, endpoint, dev) }()

	var firstErr error
	for range 2 {
		err := <-errCh
		if err == nil {
			continue
		}
		if firstErr == nil {
			firstErr = err
			cancel(err)
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// ForwardUplink 将本地设备读到的 IP 包转发到远端，并处理远端返回的 ICMP 响应。
func (p *PacketIO) ForwardUplink(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
	if dev == nil {
		return fmt.Errorf(errPacketIOTUNRequired, config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf(errPacketIOEndpointRequired, config.ErrInvalidConfig)
	}

	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}

		buf, n, err := p.readUplinkPacket(ctx, dev)
		if err != nil {
			return err
		}
		if buf == nil {
			continue
		}
		if n <= 0 {
			p.pool.Put(buf)
			continue
		}
		if p.stats.Snapshot().TxPackets == 0 {
			p.logf("first uplink packet observed bytes=%d device=%q %s", n, dev.Name(), packetSummary(buf.Data[:n]))
		}
		p.tracePacket("uplink", n, dev.Name(), buf.Data[:n])

		if err := p.forwardUplinkFragments(ctx, dev, endpoint, buf.Data[:n]); err != nil {
			p.pool.Put(buf)
			return err
		}
		p.pool.Put(buf)
	}
}

// ForwardDownlink 将远端返回的 IP 包写回本地设备。
func (p *PacketIO) ForwardDownlink(ctx context.Context, endpoint PacketRelayEndpoint, dev TUNDevice) error {
	if dev == nil {
		return fmt.Errorf(errPacketIOTUNRequired, config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf(errPacketIOEndpointRequired, config.ErrInvalidConfig)
	}

	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}

		buf, n, err := p.readDownlinkPacket(ctx, endpoint)
		if err != nil {
			return err
		}
		if buf == nil {
			continue
		}
		if n <= 0 {
			p.pool.Put(buf)
			continue
		}
		if p.stats.Snapshot().RxPackets == 0 {
			p.logf("first downlink packet observed bytes=%d device=%q %s", n, dev.Name(), packetSummary(buf.Data[:n]))
		}
		p.tracePacket("downlink", n, dev.Name(), buf.Data[:n])

		err = p.writeDownlinkPacket(ctx, dev, buf.Data[:n], n)
		p.pool.Put(buf)
		if err != nil {
			return err
		}
		p.stats.AddRx(n)
	}
}

func (p *PacketIO) readUplinkPacket(ctx context.Context, dev TUNDevice) (*packet.Buffer, int, error) {
	buf := p.pool.Get()
	n, err := dev.ReadPacket(ctx, buf.Data)
	if err == nil {
		return buf, n, nil
	}
	p.pool.Put(buf)
	if idle, idleErr := normalizeRelayReadError(ctx, err); idle {
		if idleErr != nil {
			return nil, 0, idleErr
		}
		return nil, 0, nil
	}
	return nil, 0, fmt.Errorf("uplink read packet: %w", err)
}

func (p *PacketIO) forwardUplinkFragments(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint, packet []byte) error {
	for _, fragment := range splitPacketByMTU(packet, p.mtu) {
		if err := p.forwardUplinkFragment(ctx, dev, endpoint, fragment); err != nil {
			return err
		}
	}
	return nil
}

func (p *PacketIO) forwardUplinkFragment(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint, fragment []byte) error {
	icmp, writeErr := endpoint.WritePacket(ctx, fragment)
	if err := p.writeICMPPacket(ctx, dev, icmp); err != nil {
		return err
	}
	if writeErr != nil {
		return fmt.Errorf("uplink write packet: %w", writeErr)
	}
	p.stats.AddTx(len(fragment))
	return nil
}

func (p *PacketIO) writeICMPPacket(ctx context.Context, dev TUNDevice, packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	written, err := dev.WritePacket(ctx, packet)
	if err != nil {
		return fmt.Errorf("uplink write icmp packet: %w", err)
	}
	if written != len(packet) {
		return fmt.Errorf("uplink write icmp packet: %w", io.ErrShortWrite)
	}
	p.stats.AddRx(len(packet))
	return nil
}

func (p *PacketIO) readDownlinkPacket(ctx context.Context, endpoint PacketRelayEndpoint) (*packet.Buffer, int, error) {
	buf := p.pool.Get()
	n, err := endpoint.ReadPacket(ctx, buf.Data)
	if err == nil {
		return buf, n, nil
	}
	p.pool.Put(buf)
	if idle, idleErr := normalizeRelayReadError(ctx, err); idle {
		if idleErr != nil {
			return nil, 0, idleErr
		}
		return nil, 0, nil
	}
	return nil, 0, fmt.Errorf("downlink read packet: %w", err)
}

func (p *PacketIO) writeDownlinkPacket(ctx context.Context, dev TUNDevice, packet []byte, want int) error {
	written, err := dev.WritePacket(ctx, packet)
	if err != nil {
		return fmt.Errorf("downlink write packet: %w", err)
	}
	if written != want {
		return fmt.Errorf("downlink write packet: %w", io.ErrShortWrite)
	}
	return nil
}

func (p *PacketIO) logf(format string, args ...any) {
	if p == nil || p.logger == nil {
		return
	}
	p.logger.Printf(format, args...)
}

func (p *PacketIO) tracePacket(direction string, n int, device string, packet []byte) {
	if p == nil || p.traceLimit <= 0 {
		return
	}
	switch direction {
	case "uplink":
		if p.uplinkTraceSeen >= p.traceLimit {
			return
		}
		p.uplinkTraceSeen++
		p.logf("%s packet #%d bytes=%d device=%q %s", direction, p.uplinkTraceSeen, n, device, packetSummary(packet))
	case "downlink":
		if p.downlinkTraceSeen >= p.traceLimit {
			return
		}
		p.downlinkTraceSeen++
		p.logf("%s packet #%d bytes=%d device=%q %s", direction, p.downlinkTraceSeen, n, device, packetSummary(packet))
	}
}

func packetTraceLimitFromEnv() int {
	value := os.Getenv("AMZ_TUN_TRACE_PACKETS")
	if value == "" {
		return 1
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 1
	}
	return n
}

func packetSummary(packet []byte) string {
	if len(packet) < 1 {
		return "packet=empty"
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < 20 {
			return "packet=ipv4_truncated"
		}
		src := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		dst := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		proto := ipProtocolName(packet[9])
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen == 0 {
			totalLen = len(packet)
		}
		return fmt.Sprintf("version=4 src=%s dst=%s proto=%s total_len=%d", src, dst, proto, totalLen)
	case 6:
		if len(packet) < 40 {
			return "packet=ipv6_truncated"
		}
		var srcRaw, dstRaw [16]byte
		copy(srcRaw[:], packet[8:24])
		copy(dstRaw[:], packet[24:40])
		src := netip.AddrFrom16(srcRaw)
		dst := netip.AddrFrom16(dstRaw)
		proto := ipProtocolName(packet[6])
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		return fmt.Sprintf("version=6 src=%s dst=%s proto=%s payload_len=%d", src, dst, proto, payloadLen)
	default:
		return fmt.Sprintf("packet=unknown_version_%d", version)
	}
}

func ipProtocolName(proto byte) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

func normalizeRelayReadError(ctx context.Context, err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return true, cause
	}
	if errors.Is(err, io.EOF) {
		timer := time.NewTimer(packetIdleBackoff)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return true, context.Cause(ctx)
		case <-timer.C:
			return true, nil
		}
	}
	return false, nil
}

func splitPacketByMTU(payload []byte, mtu int) [][]byte {
	if len(payload) == 0 {
		return nil
	}
	if mtu <= 0 || len(payload) <= mtu {
		return [][]byte{append([]byte(nil), payload...)}
	}

	fragments := make([][]byte, 0, (len(payload)+mtu-1)/mtu)
	for start := 0; start < len(payload); start += mtu {
		end := start + mtu
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, append([]byte(nil), payload[start:end]...))
	}
	return fragments
}
