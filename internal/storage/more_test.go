package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateNormalizedAndDefaultState(t *testing.T) {
	state := State{}
	normalized := state.normalized()
	if normalized.Version != CurrentVersion {
		t.Fatalf("expected version %q, got %q", CurrentVersion, normalized.Version)
	}
	if normalized.NodeCache == nil {
		t.Fatal("expected node cache slice to be initialized")
	}
	defaultState := DefaultState()
	if defaultState.Version != CurrentVersion || defaultState.NodeCache == nil {
		t.Fatalf("unexpected default state: %+v", defaultState)
	}
}

func TestReadAndWriteErrorBranches(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "read state") {
		t.Fatalf("expected read error, got %v", err)
	}
	badDir := filepath.Join(t.TempDir(), "dir")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatalf("expected mkdir success, got %v", err)
	}
	if err := Write(badDir, State{}); err == nil || !strings.Contains(err.Error(), "write state") {
		t.Fatalf("expected write error for directory target, got %v", err)
	}
	badJSON := filepath.Join(t.TempDir(), "bad.json")
	if err := osWriteFileString(badJSON, "not-json"); err != nil {
		t.Fatalf("expected helper write success, got %v", err)
	}
	if _, err := Read(badJSON); err == nil || !strings.Contains(err.Error(), "unmarshal state") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestFileStoreNilReceiverErrors(t *testing.T) {
	var store *FileStore
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "file store is required") {
		t.Fatalf("expected nil load error, got %v", err)
	}
	if err := store.Save(State{}); err == nil || !strings.Contains(err.Error(), "file store is required") {
		t.Fatalf("expected nil save error, got %v", err)
	}
}

func TestStateJSONRoundTripIncludesOptionalSections(t *testing.T) {
	state := State{
		Version:      CurrentVersion,
		DeviceID:     "device-1",
		Token:        "token-1",
		Certificate:  Certificate{PrivateKey: "priv", ClientCertificate: "cert", PeerPublicKey: "peer", ClientID: "cid"},
		Account:      AccountStatus{State: "registered", AccountType: "plus"},
		Interface:    InterfaceAddresses{V4: "1.1.1.1", V6: "::1"},
		Services:     Services{HTTPProxy: "http://proxy"},
		SelectedNode: "node-1",
		NodeCache:    []Node{{ID: "node-1", Host: "host", EndpointV4: "1.1.1.1:443", EndpointV6: "[::1]:443", PublicKey: "peer", Ports: []uint16{443}}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("expected marshal success, got %v", err)
	}
	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("expected unmarshal success, got %v", err)
	}
	if decoded.Services.HTTPProxy != "http://proxy" || decoded.NodeCache[0].ID != "node-1" {
		t.Fatalf("unexpected decoded state: %+v", decoded)
	}
}

func TestDefaultPathFallbackToUserConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("expected default path success, got %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("amz", "state.json")) {
		t.Fatalf("unexpected default path suffix: %q", path)
	}
}

func osWriteFileString(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
