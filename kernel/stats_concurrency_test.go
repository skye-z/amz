package kernel

import (
	"sync"
	"testing"
	"time"
)

// 验证轻量统计骨架在并发累加时能保持一致快照。
func TestConnectionStatsConcurrentUpdates(t *testing.T) {
	const workers = 16
	const iterations = 200

	var stats connectionStats
	stats.RecordHandshakeLatency(25 * time.Millisecond)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				stats.AddTxBytes(1)
				stats.AddRxBytes(2)
				stats.AddReconnect()
			}
		}()
	}
	wg.Wait()

	snapshot := stats.Snapshot()
	if snapshot.TxBytes != workers*iterations {
		t.Fatalf("expected tx bytes %d, got %d", workers*iterations, snapshot.TxBytes)
	}
	if snapshot.RxBytes != workers*iterations*2 {
		t.Fatalf("expected rx bytes %d, got %d", workers*iterations*2, snapshot.RxBytes)
	}
	if snapshot.ReconnectCount != workers*iterations {
		t.Fatalf("expected reconnect count %d, got %d", workers*iterations, snapshot.ReconnectCount)
	}
	if snapshot.HandshakeLatency != 25*time.Millisecond {
		t.Fatalf("expected handshake latency %s, got %s", 25*time.Millisecond, snapshot.HandshakeLatency)
	}
}
