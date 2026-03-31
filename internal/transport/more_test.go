package transport

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestSplitPacketByMTUAndNormalizeRelayReadError(t *testing.T) {
	fragments := splitPacketByMTU([]byte{1,2,3,4,5}, 2)
	if len(fragments) != 3 || len(fragments[2]) != 1 {
		t.Fatalf("unexpected fragments: %+v", fragments)
	}
	if got := splitPacketByMTU([]byte{1,2}, 0); len(got) != 1 {
		t.Fatalf("expected single fragment for mtu<=0, got %+v", got)
	}
	if got := splitPacketByMTU(nil, 2); got != nil {
		t.Fatalf("expected nil fragments for empty payload, got %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if idle, err := normalizeRelayReadError(ctx, io.EOF); !idle || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled idle error, got idle=%v err=%v", idle, err)
	}
	if idle, err := normalizeRelayReadError(context.Background(), errors.New("boom")); idle || err != nil {
		t.Fatalf("expected non-idle generic error, got idle=%v err=%v", idle, err)
	}
}
