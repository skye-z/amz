package socks5

import (
	"context"
	"testing"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

func TestNewManagerFillsDefaultListenAddress(t *testing.T) {
	t.Parallel()

	mgr, err := NewManager(&config.KernelConfig{
		Endpoint: config.DefaultEndpoint,
		SNI:      config.DefaultSNI,
		MTU:      config.DefaultMTU,
		Mode:     config.ModeSOCKS,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if mgr.ListenAddress() != config.DefaultSOCKSListenAddress {
		t.Fatalf("expected default listen address %q, got %q", config.DefaultSOCKSListenAddress, mgr.ListenAddress())
	}
	if mgr.State() != types.StateIdle {
		t.Fatalf("expected idle state, got %q", mgr.State())
	}
}

func TestManagerStartStopAndSnapshot(t *testing.T) {
	t.Parallel()

	mgr, err := NewManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: "127.0.0.1:0",
			Username:      "demo",
			Password:      "secret",
			EnableUDP:     true,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	snapshot := mgr.Snapshot()
	if snapshot.Username != "demo" {
		t.Fatalf("expected username demo, got %q", snapshot.Username)
	}
	if !snapshot.EnableUDP {
		t.Fatal("expected udp associate enabled")
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if mgr.ListenAddress() == "127.0.0.1:0" {
		t.Fatalf("expected runtime listen address update, got %q", mgr.ListenAddress())
	}
	if mgr.State() != types.StateRunning {
		t.Fatalf("expected running state, got %q", mgr.State())
	}

	stats := mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 0 {
		t.Fatalf("expected start stats, got %+v", stats)
	}

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop success, got %v", err)
	}
	if mgr.State() != types.StateStopped {
		t.Fatalf("expected stopped state, got %q", mgr.State())
	}

	stats = mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 1 {
		t.Fatalf("expected stop stats, got %+v", stats)
	}
}
