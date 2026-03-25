package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/packet"
)

const packetIdleBackoff = 5 * time.Millisecond
const maxPacketBufferSize = 65535

// 约定隧道远端最小数据面收发接口。
type PacketRelayEndpoint interface {
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) ([]byte, error)
	Close() error
}

// 描述数据面的最小包收发骨架。
type PacketIO struct {
	mtu   int
	pool  *packet.BufferPool
	stats *packet.Stats
}

// 创建带缓冲池和统计的最小数据面对象。
func NewPacketIO(mtu int) *PacketIO {
	if mtu <= 0 {
		mtu = config.DefaultMTU
	}
	return &PacketIO{
		mtu:   mtu,
		pool:  packet.NewBufferPool(maxPacketBufferSize),
		stats: packet.NewStats(),
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

// Relay 启动双向收发循环，并在上下文结束时关闭远端数据面。
func (p *PacketIO) Relay(ctx context.Context, dev TUNDevice, endpoint PacketRelayEndpoint) error {
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf("%w: packet relay endpoint is required", config.ErrInvalidConfig)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	defer func() { _ = endpoint.Close() }()

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
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf("%w: packet relay endpoint is required", config.ErrInvalidConfig)
	}

	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}

		buf := p.pool.Get()
		n, err := dev.ReadPacket(ctx, buf.Data)
		if err != nil {
			p.pool.Put(buf)
			if idle, idleErr := normalizeRelayReadError(ctx, err); idle {
				if idleErr != nil {
					return idleErr
				}
				continue
			}
			return fmt.Errorf("uplink read packet: %w", err)
		}
		if n <= 0 {
			p.pool.Put(buf)
			continue
		}

		fragments := splitPacketByMTU(buf.Data[:n], p.mtu)
		for _, fragment := range fragments {
			icmp, writeErr := endpoint.WritePacket(ctx, fragment)
			if len(icmp) > 0 {
				written, err := dev.WritePacket(ctx, icmp)
				if err != nil {
					p.pool.Put(buf)
					return fmt.Errorf("uplink write icmp packet: %w", err)
				}
				if written != len(icmp) {
					p.pool.Put(buf)
					return fmt.Errorf("uplink write icmp packet: %w", io.ErrShortWrite)
				}
				p.stats.AddRx(len(icmp))
			}
			if writeErr != nil {
				p.pool.Put(buf)
				return fmt.Errorf("uplink write packet: %w", writeErr)
			}
			p.stats.AddTx(len(fragment))
		}
		p.pool.Put(buf)
	}
}

// ForwardDownlink 将远端返回的 IP 包写回本地设备。
func (p *PacketIO) ForwardDownlink(ctx context.Context, endpoint PacketRelayEndpoint, dev TUNDevice) error {
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
	}
	if endpoint == nil {
		return fmt.Errorf("%w: packet relay endpoint is required", config.ErrInvalidConfig)
	}

	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}

		buf := p.pool.Get()
		n, err := endpoint.ReadPacket(ctx, buf.Data)
		if err != nil {
			p.pool.Put(buf)
			if idle, idleErr := normalizeRelayReadError(ctx, err); idle {
				if idleErr != nil {
					return idleErr
				}
				continue
			}
			return fmt.Errorf("downlink read packet: %w", err)
		}
		if n <= 0 {
			p.pool.Put(buf)
			continue
		}

		written, err := dev.WritePacket(ctx, buf.Data[:n])
		p.pool.Put(buf)
		if err != nil {
			return fmt.Errorf("downlink write packet: %w", err)
		}
		if written != n {
			return fmt.Errorf("downlink write packet: %w", io.ErrShortWrite)
		}
		p.stats.AddRx(n)
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
