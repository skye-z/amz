package kernel_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/types"
)

// 验证 SOCKS5 轻量管理器在并发启动停止时只记录一次生命周期切换。
func TestSOCKSManagerConcurrentStartStopCountsOnce(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	runConcurrentLifecycle(t, mgr)

	stats := mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 1 {
		t.Fatalf("expected one start and one stop, got %+v", stats)
	}
	if mgr.State() != types.StateStopped {
		t.Fatalf("expected stopped state, got %q", mgr.State())
	}
}

// 验证 HTTP 轻量管理器在并发启动停止时只记录一次生命周期切换。
func TestHTTPProxyManagerConcurrentStartStopCountsOnce(t *testing.T) {
	mgr, err := kernel.NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: config.DefaultHTTPListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	runConcurrentLifecycle(t, mgr)

	stats := mgr.Stats()
	if stats.StartCount != 1 || stats.StopCount != 1 {
		t.Fatalf("expected one start and one stop, got %+v", stats)
	}
	if mgr.State() != types.StateStopped {
		t.Fatalf("expected stopped state, got %q", mgr.State())
	}
}

// 验证 SOCKS5 轻量管理器会在并发资源统计更新后返回一致快照。
func TestSOCKSManagerConcurrentResourceStats(t *testing.T) {
	mgr, err := kernel.NewSOCKSManager(&config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	assertConcurrentResourceStats(t,
		func(latency time.Duration) { mgr.RecordHandshakeLatency(latency) },
		mgr.AddTxBytes,
		mgr.AddRxBytes,
		mgr.AddReconnect,
		mgr.Stats,
	)
}

// 验证 HTTP 轻量管理器会在并发资源统计更新后返回一致快照。
func TestHTTPProxyManagerConcurrentResourceStats(t *testing.T) {
	mgr, err := kernel.NewHTTPProxyManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeHTTP,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		HTTP: config.HTTPConfig{
			ListenAddress: config.DefaultHTTPListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	assertConcurrentResourceStats(t,
		func(latency time.Duration) { mgr.RecordHandshakeLatency(latency) },
		mgr.AddTxBytes,
		mgr.AddRxBytes,
		mgr.AddReconnect,
		mgr.Stats,
	)
}

// 并发触发生命周期操作，验证最小骨架的幂等性。
func runConcurrentLifecycle(t *testing.T, tunnel types.Tunnel) {
	t.Helper()

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tunnel.Start(context.Background()); err != nil {
				t.Errorf("expected start success, got %v", err)
			}
		}()
	}
	wg.Wait()

	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tunnel.Stop(context.Background()); err != nil {
				t.Errorf("expected stop success, got %v", err)
			}
		}()
	}
	wg.Wait()
}

// 并发写入轻量资源统计并校验最终快照。
func assertConcurrentResourceStats(
	t *testing.T,
	recordHandshake func(time.Duration),
	addTx func(int),
	addRx func(int),
	addReconnect func(),
	snapshot func() types.Stats,
) {
	t.Helper()

	const workers = 16
	const iterations = 128

	recordHandshake(42 * time.Millisecond)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				addTx(1)
				addRx(2)
				addReconnect()
			}
		}()
	}
	wg.Wait()

	stats := snapshot()
	if stats.TxBytes != workers*iterations {
		t.Fatalf("expected tx bytes %d, got %d", workers*iterations, stats.TxBytes)
	}
	if stats.RxBytes != workers*iterations*2 {
		t.Fatalf("expected rx bytes %d, got %d", workers*iterations*2, stats.RxBytes)
	}
	if stats.ReconnectCount != workers*iterations {
		t.Fatalf("expected reconnect count %d, got %d", workers*iterations, stats.ReconnectCount)
	}
	if stats.HandshakeLatency != 42*time.Millisecond {
		t.Fatalf("expected handshake latency %s, got %s", 42*time.Millisecond, stats.HandshakeLatency)
	}
}
