package kernel_test

import (
	"testing"

	"github.com/skye-z/amz/kernel"
)

// 验证数据面会暴露最小收发接口与统计信息。
func TestNewPacketIO(t *testing.T) {
	io := kernel.NewPacketIO(1600)
	if io.MTU() != 1600 {
		t.Fatalf("expected mtu 1600, got %d", io.MTU())
	}
	stats := io.Stats()
	if stats.RxPackets != 0 || stats.TxPackets != 0 {
		t.Fatalf("expected zero stats, got %+v", stats)
	}
}
