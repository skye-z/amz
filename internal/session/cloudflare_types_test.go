package session

import (
	"testing"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
	"github.com/skye-z/amz/internal/testkit"
)

func TestDefaultCloudflareQuirksUsesInternalAlias(t *testing.T) {
	quirks := DefaultCloudflareQuirks()
	if _, ok := any(quirks).(internalcloudflare.Quirks); !ok {
		t.Fatalf("expected cloudflare quirks to use internal alias, got %T", quirks)
	}
	if quirks.Name == "" || !quirks.UseCFConnectIP || !quirks.RequireDatagrams {
		t.Fatalf("unexpected default quirks: %+v", quirks)
	}
}

func TestCloudflareSnapshotUsesInternalAlias(t *testing.T) {
	snapshot := CloudflareSnapshot{Protocol: ProtocolCFConnectIP, Endpoint: testkit.WarpIPv4Alt443}
	if _, ok := any(snapshot).(internalcloudflare.Snapshot); !ok {
		t.Fatalf("expected cloudflare snapshot to use internal alias, got %T", snapshot)
	}
	if snapshot.Protocol != internalcloudflare.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", internalcloudflare.ProtocolCFConnectIP, snapshot.Protocol)
	}
}
