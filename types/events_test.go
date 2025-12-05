package types_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/types"
)

// 验证事件结构可表达基础生命周期变化。
func TestEvent(t *testing.T) {
	event := types.Event{
		Type:      types.EventTypeStateChanged,
		State:     types.StateRunning,
		Message:   "connected",
		Timestamp: time.Unix(1700000000, 0),
	}

	if event.Type != types.EventTypeStateChanged {
		t.Fatalf("expected event type %q, got %q", types.EventTypeStateChanged, event.Type)
	}
	if event.State != types.StateRunning {
		t.Fatalf("expected state %q, got %q", types.StateRunning, event.State)
	}
	if event.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}
}
