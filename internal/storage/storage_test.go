package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skye-z/amz/internal/testkit"
)

func TestDefaultPathUsesAMZStateJSON(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))

	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("expected default path, got %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("amz", "state.json")) {
		t.Fatalf("expected amz state path, got %q", path)
	}
}

func TestReadWritePreservesAMZStateOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	input := State{
		DeviceID: "device-123",
		Token:    "token-123",
		Certificate: Certificate{
			PrivateKey:        "private-key-123",
			ClientCertificate: "client-cert-123",
			PeerPublicKey:     "peer-public-key-123",
			ClientID:          "client-id-123",
		},
		Account: AccountStatus{
			State:       "registered",
			AccountType: "plus",
		},
		SelectedNode: "node-2",
		NodeCache: []Node{
			{
				ID:         "node-1",
				Host:       testkit.WarpHostPrimary,
				EndpointV4: testkit.WarpIPv4Primary443,
				EndpointV6: testkit.WarpIPv6Primary443,
				PublicKey:  "peer-1",
				Ports:      []uint16{443, 500},
			},
			{
				ID:         "node-2",
				Host:       testkit.WarpHostProxy500,
				EndpointV4: testkit.WarpIPv4Alt500,
				EndpointV6: testkit.WarpIPv6Alt500,
				PublicKey:  "peer-2",
				Ports:      []uint16{500},
			},
		},
	}

	if err := Write(path, input); err != nil {
		t.Fatalf("expected write success, got %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected raw file, got %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "\"registration\"") {
		t.Fatalf("expected new state format without igara registration wrapper, got %s", text)
	}
	if !strings.Contains(text, "\"device_id\"") {
		t.Fatalf("expected device id in state file, got %s", text)
	}

	output, err := Read(path)
	if err != nil {
		t.Fatalf("expected read success, got %v", err)
	}
	if output.Version != CurrentVersion {
		t.Fatalf("expected version %q, got %q", CurrentVersion, output.Version)
	}
	if output.DeviceID != input.DeviceID {
		t.Fatalf("expected device id round trip, got %q", output.DeviceID)
	}
	if output.Token != input.Token {
		t.Fatalf("expected token round trip, got %q", output.Token)
	}
	if output.Certificate.PrivateKey != input.Certificate.PrivateKey {
		t.Fatalf("expected private key round trip, got %q", output.Certificate.PrivateKey)
	}
	if output.Certificate.ClientCertificate != input.Certificate.ClientCertificate {
		t.Fatalf("expected client certificate round trip, got %q", output.Certificate.ClientCertificate)
	}
	if output.Certificate.PeerPublicKey != input.Certificate.PeerPublicKey {
		t.Fatalf("expected peer public key round trip, got %q", output.Certificate.PeerPublicKey)
	}
	if output.Certificate.ClientID != input.Certificate.ClientID {
		t.Fatalf("expected client id round trip, got %q", output.Certificate.ClientID)
	}
	if output.Account.State != input.Account.State {
		t.Fatalf("expected account state round trip, got %q", output.Account.State)
	}
	if output.Account.AccountType != input.Account.AccountType {
		t.Fatalf("expected account type round trip, got %q", output.Account.AccountType)
	}
	if output.SelectedNode != input.SelectedNode {
		t.Fatalf("expected selected node round trip, got %q", output.SelectedNode)
	}
	if len(output.NodeCache) != len(input.NodeCache) {
		t.Fatalf("expected node cache length %d, got %d", len(input.NodeCache), len(output.NodeCache))
	}
	if output.NodeCache[1].ID != "node-2" {
		t.Fatalf("expected node cache to preserve second node, got %+v", output.NodeCache[1])
	}
}

func TestFileStoreLoadAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	store := NewFileStore(path)
	want := State{
		DeviceID: "device-123",
		Token:    "token-123",
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("expected save success, got %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("expected load success, got %v", err)
	}
	if got.DeviceID != want.DeviceID {
		t.Fatalf("expected device id %q, got %q", want.DeviceID, got.DeviceID)
	}
	if got.Token != want.Token {
		t.Fatalf("expected token %q, got %q", want.Token, got.Token)
	}
}
