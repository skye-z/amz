package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/skye-z/amz/internal/config"
)

func TestBootstrapTUNManagerStartInvokesPrepare(t *testing.T) {
	t.Parallel()

	bootstrap := &stubTUNBootstrap{}
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, bootstrap)
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if !bootstrap.prepareCalled {
		t.Fatal("expected Prepare to be called")
	}
	if manager.State() != config.StateRunning {
		t.Fatalf("expected running state, got %q", manager.State())
	}
}

func TestBootstrapTUNManagerCloseInvokesBootstrapClose(t *testing.T) {
	t.Parallel()

	bootstrap := &stubTUNBootstrap{}
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, bootstrap)
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if !bootstrap.closeCalled {
		t.Fatal("expected bootstrap Close to be called")
	}
	if manager.State() != config.StateStopped {
		t.Fatalf("expected stopped state, got %q", manager.State())
	}
}

func TestBootstrapTUNManagerPropagatesPrepareError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("prepare failed")
	manager, err := NewBootstrapTUNManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeTUN,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		TUN:            config.TUNConfig{Name: "igara-test0"},
	}, &stubTUNBootstrap{prepareErr: wantErr})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected prepare error %v, got %v", wantErr, err)
	}
}

type stubTUNBootstrap struct {
	prepareCalled bool
	closeCalled   bool
	prepareErr    error
	closeErr      error
}

func (s *stubTUNBootstrap) Prepare(context.Context) error {
	s.prepareCalled = true
	return s.prepareErr
}

func (s *stubTUNBootstrap) Close() error {
	s.closeCalled = true
	return s.closeErr
}
