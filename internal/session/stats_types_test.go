package session

import (
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
)

func TestConnectionStatsUsesTypesAlias(t *testing.T) {
	stats := &connectionStats{}
	stats.RecordHandshakeLatency(25 * time.Millisecond)
	stats.AddTxBytes(64)
	stats.AddRxBytes(32)

	snapshot := stats.Snapshot()
	if snapshot.HandshakeLatency != 25*time.Millisecond || snapshot.TxBytes != 64 || snapshot.RxBytes != 32 {
		t.Fatalf("unexpected stats snapshot: %+v", snapshot)
	}
	if _, ok := any(stats).(*config.ConnectionStats); !ok {
		t.Fatalf("expected connection stats to use config alias, got %T", stats)
	}
}
