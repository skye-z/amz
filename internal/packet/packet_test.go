package packet_test

import (
	"testing"

	"github.com/skye-z/amz/internal/packet"
)

// 验证数据包缓冲可复用并保留长度信息。
func TestBufferPool(t *testing.T) {
	pool := packet.NewBufferPool(1600)
	buf := pool.Get()
	if len(buf.Data) != 1600 {
		t.Fatalf("expected buffer size 1600, got %d", len(buf.Data))
	}
	buf.N = 128
	pool.Put(buf)

	buf2 := pool.Get()
	if buf2.N != 0 {
		t.Fatalf("expected reset length, got %d", buf2.N)
	}
}

// 验证收发统计会记录上下行包计数。
func TestStats(t *testing.T) {
	stats := packet.NewStats()
	stats.AddRx(120)
	stats.AddTx(64)
	if stats.Snapshot().RxPackets != 1 {
		t.Fatalf("expected 1 rx packet, got %d", stats.Snapshot().RxPackets)
	}
	if stats.Snapshot().TxPackets != 1 {
		t.Fatalf("expected 1 tx packet, got %d", stats.Snapshot().TxPackets)
	}
}
