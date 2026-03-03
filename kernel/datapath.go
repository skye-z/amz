package kernel

import "github.com/skye-z/amz/internal/packet"

// PacketIO 描述数据面的最小包收发骨架。
type PacketIO struct {
	mtu   int
	pool  *packet.BufferPool
	stats *packet.Stats
}

// NewPacketIO 创建带缓冲池和统计的最小数据面对象。
func NewPacketIO(mtu int) *PacketIO {
	return &PacketIO{
		mtu:   mtu,
		pool:  packet.NewBufferPool(mtu),
		stats: packet.NewStats(),
	}
}

// MTU 返回当前数据面使用的 MTU。
func (p *PacketIO) MTU() int {
	return p.mtu
}

// Stats 返回当前数据面的最小统计信息。
func (p *PacketIO) Stats() packet.Snapshot {
	return p.stats.Snapshot()
}
