package types_test

import (
	"testing"
	"time"

	"github.com/skye-z/amz/types"
)

// 验证事件回调可接收生命周期事件。
func TestEventHandler(t *testing.T) {
	called := false
	handler := types.EventHandler(func(event types.Event) {
		called = true
		if event.Type != types.EventTypeStateChanged {
			t.Fatalf("expected event type %q, got %q", types.EventTypeStateChanged, event.Type)
		}
	})

	handler(types.Event{Type: types.EventTypeStateChanged, Timestamp: time.Now()})

	if !called {
		t.Fatal("expected handler to be called")
	}
}
