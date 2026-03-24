package observe

import (
	"sync"
	"time"
)

type ConnectionStats struct {
	mu    sync.Mutex
	stats Stats
}

func (s *ConnectionStats) RecordHandshakeLatency(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.HandshakeLatency = latency
}

func (s *ConnectionStats) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TxBytes += n
}

func (s *ConnectionStats) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.RxBytes += n
}

func (s *ConnectionStats) AddReconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ReconnectCount++
}

func (s *ConnectionStats) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
