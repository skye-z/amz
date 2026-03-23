package kernel

import (
	"sync"
	"time"

	"github.com/skye-z/amz/types"
)

// 聚合连接阶段对上层暴露的最小统计信息。
type connectionStats struct {
	mu    sync.Mutex
	stats types.Stats
}

// 记录最近一次握手时延。
func (s *connectionStats) RecordHandshakeLatency(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.HandshakeLatency = latency
}

// 累加上行字节数。
func (s *connectionStats) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TxBytes += n
}

// 累加下行字节数。
func (s *connectionStats) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.RxBytes += n
}

// 累加重连次数。
func (s *connectionStats) AddReconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ReconnectCount++
}

// 返回统计快照。
func (s *connectionStats) Snapshot() types.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
