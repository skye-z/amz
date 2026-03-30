package tun

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"

	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/skye-z/amz/internal/testkit"
)

type fakeNativeTun struct {
	options      []singtun.Options
	failUpdateAt int
	startCalls   int
	startErr     error
	startedWith  singtun.Options
	createdWith  singtun.Options
}

func (f *fakeNativeTun) Read([]byte) (int, error)    { return 0, io.EOF }
func (f *fakeNativeTun) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeNativeTun) Name() (string, error)       { return "amz0", nil }
func (f *fakeNativeTun) Start() error {
	f.startCalls++
	f.startedWith = f.createdWith
	return f.startErr
}
func (f *fakeNativeTun) Close() error { return nil }
func (f *fakeNativeTun) UpdateRouteOptions(o singtun.Options) error {
	f.options = append(f.options, o)
	if f.failUpdateAt > 0 && len(f.options) == f.failUpdateAt {
		return errors.New("update failed")
	}
	return nil
}

// 验证 sing-tun 设备会将地址与路由转换为真实 route options。
func TestSingDeviceApplyTUNConfigAndRoutes(t *testing.T) {
	nativeTun := &fakeNativeTun{}
	device := &singDevice{
		tun:     nativeTun,
		name:    "amz0",
		mtu:     1400,
		started: false,
		options: singtun.Options{
			Name:      "amz0",
			MTU:       1400,
			AutoRoute: false,
		},
	}

	if err := device.ApplyTUNConfig(Config{
		Device: DeviceConfig{Name: "amz0", MTU: 1400},
		Addresses: []Address{
			{CIDR: testkit.TunIPv4CIDR},
			{CIDR: testkit.TunIPv6CIDR},
		},
	}); err != nil {
		t.Fatalf("expected apply config success, got %v", err)
	}
	if err := device.ApplyTUNRoutes(RoutePlan{
		Mode:           RouteModeSplit,
		Routes:         []string{testkit.RouteSplitV4, testkit.RouteSplitV6},
		EndpointRoutes: []string{testkit.EndpointRouteV4, testkit.EndpointRouteV6},
	}); err != nil {
		t.Fatalf("expected apply routes success, got %v", err)
	}

	if len(nativeTun.options) != 0 {
		t.Fatalf("expected no native updates before start, got %d", len(nativeTun.options))
	}
	got := device.options
	if got.AutoRoute {
		t.Fatalf("expected split mode to keep autoroute disabled, got %+v", got)
	}
	if len(got.Inet4Address) != 1 || got.Inet4Address[0] != netip.MustParsePrefix(testkit.TunIPv4CIDR) {
		t.Fatalf("unexpected inet4 address options: %+v", got.Inet4Address)
	}
	if len(got.Inet6Address) != 1 || got.Inet6Address[0] != netip.MustParsePrefix(testkit.TunIPv6CIDR) {
		t.Fatalf("unexpected inet6 address options: %+v", got.Inet6Address)
	}
	if len(got.Inet4RouteAddress) != 1 || got.Inet4RouteAddress[0] != netip.MustParsePrefix(testkit.RouteSplitV4) {
		t.Fatalf("unexpected inet4 route options: %+v", got.Inet4RouteAddress)
	}
	if len(got.Inet6RouteAddress) != 1 || got.Inet6RouteAddress[0] != netip.MustParsePrefix(testkit.RouteSplitV6) {
		t.Fatalf("unexpected inet6 route options: %+v", got.Inet6RouteAddress)
	}
	if len(got.Inet4RouteExcludeAddress) != 1 || got.Inet4RouteExcludeAddress[0] != netip.MustParsePrefix(testkit.EndpointRouteV4) {
		t.Fatalf("unexpected inet4 route exclude options: %+v", got.Inet4RouteExcludeAddress)
	}
	if len(got.Inet6RouteExcludeAddress) != 1 || got.Inet6RouteExcludeAddress[0] != netip.MustParsePrefix(testkit.EndpointRouteV6) {
		t.Fatalf("unexpected inet6 route exclude options: %+v", got.Inet6RouteExcludeAddress)
	}
}

// 验证 sing-tun 设备会在路由更新失败时执行回滚。
func TestSingDeviceApplyTUNRoutesRollbackOnFailure(t *testing.T) {
	nativeTun := &fakeNativeTun{failUpdateAt: 2}
	device := &singDevice{
		tun:     nativeTun,
		name:    "amz0",
		mtu:     1400,
		started: true,
		options: singtun.Options{
			Name:      "amz0",
			MTU:       1400,
			AutoRoute: false,
		},
	}

	if err := device.ApplyTUNConfig(Config{
		Device: DeviceConfig{Name: "amz0", MTU: 1400},
		Addresses: []Address{
			{CIDR: testkit.TunIPv4CIDR},
		},
	}); err != nil {
		t.Fatalf("expected apply config success, got %v", err)
	}

	err := device.ApplyTUNRoutes(RoutePlan{
		Mode:           RouteModeGlobal,
		Routes:         []string{testkit.DefaultRouteV4, testkit.DefaultRouteV6},
		EndpointRoutes: []string{testkit.EndpointRouteV4, testkit.EndpointRouteV6},
	})
	if err == nil {
		t.Fatal("expected route update error")
	}
	if len(nativeTun.options) != 3 {
		t.Fatalf("expected route update + rollback, got %d updates", len(nativeTun.options))
	}
	rollback := nativeTun.options[2]
	if rollback.AutoRoute {
		t.Fatalf("expected rollback to disable autoroute, got %+v", rollback)
	}
	if len(rollback.Inet4RouteAddress) != 0 || len(rollback.Inet6RouteAddress) != 0 {
		t.Fatalf("expected rollback to restore empty route sets, got %+v", rollback)
	}
}

func TestSingProviderOpenInjectsInterfaceMonitor(t *testing.T) {
	t.Parallel()

	var networkMonitorCreated atomic.Bool
	var defaultMonitorCreated atomic.Bool
	provider := &singProvider{
		platform: "windows",
		factory: func(options singtun.Options) (singtun.Tun, error) {
			return &fakeNativeTun{}, nil
		},
		newNetworkMonitor: func() (singtun.NetworkUpdateMonitor, error) {
			networkMonitorCreated.Store(true)
			return &stubNetworkMonitor{}, nil
		},
		newDefaultMonitor: func(networkMonitor singtun.NetworkUpdateMonitor) (singtun.DefaultInterfaceMonitor, error) {
			defaultMonitorCreated.Store(true)
			return &stubInterfaceMonitor{}, nil
		},
	}

	dev, err := provider.Open(context.Background(), DeviceConfig{Name: "amz0", MTU: 1400})
	if err != nil {
		t.Fatalf("expected open success, got %v", err)
	}
	if dev == nil {
		t.Fatal("expected device")
	}
	singDev, ok := dev.(*singDevice)
	if !ok {
		t.Fatalf("expected singDevice, got %T", dev)
	}
	if singDev.options.InterfaceMonitor == nil {
		t.Fatal("expected InterfaceMonitor to be injected into sing-tun options")
	}
	if !networkMonitorCreated.Load() || !defaultMonitorCreated.Load() {
		t.Fatal("expected windows provider to construct real interface monitors")
	}
	if singDev.tun != nil {
		t.Fatal("expected tun creation to be delayed until StartDevice")
	}
}

func TestSingDeviceStartDeviceStartsInterfaceMonitor(t *testing.T) {
	t.Parallel()

	monitor := &stubInterfaceMonitor{}
	device := &singDevice{
		creator: func(options singtun.Options) (singtun.Tun, error) {
			return &fakeNativeTun{createdWith: options}, nil
		},
		name: "amz0",
		mtu:  1400,
		options: singtun.Options{
			Name:             "amz0",
			MTU:              1400,
			InterfaceMonitor: monitor,
		},
	}

	if err := device.StartDevice(); err != nil {
		t.Fatalf("expected start success, got %v", err)
	}
	if monitor.startCalls.Load() != 1 {
		t.Fatalf("expected interface monitor Start once, got %d", monitor.startCalls.Load())
	}
}

type stubNetworkMonitor struct{}

func (s *stubNetworkMonitor) Start() error { return nil }
func (s *stubNetworkMonitor) Close() error { return nil }
func (s *stubNetworkMonitor) RegisterCallback(singtun.NetworkUpdateCallback) *list.Element[singtun.NetworkUpdateCallback] {
	return nil
}
func (s *stubNetworkMonitor) UnregisterCallback(*list.Element[singtun.NetworkUpdateCallback]) {}

type stubInterfaceMonitor struct {
	startCalls atomic.Int32
}

func (s *stubInterfaceMonitor) Start() error {
	s.startCalls.Add(1)
	return nil
}
func (s *stubInterfaceMonitor) Close() error { return nil }
func (s *stubInterfaceMonitor) DefaultInterface() *control.Interface {
	return nil
}
func (s *stubInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (s *stubInterfaceMonitor) AndroidVPNEnabled() bool  { return false }
func (s *stubInterfaceMonitor) RegisterCallback(func(*control.Interface, int)) *list.Element[func(*control.Interface, int)] {
	return nil
}
func (s *stubInterfaceMonitor) UnregisterCallback(*list.Element[func(*control.Interface, int)]) {}
func (s *stubInterfaceMonitor) RegisterMyInterface(string)                                      {}
func (s *stubInterfaceMonitor) MyInterface() string                                             { return "" }

func TestAssembleStartsSingTunAfterConfigAndRoutes(t *testing.T) {
	t.Parallel()

	nativeTun := &fakeNativeTun{}
	provider := &singProvider{
		platform: "windows",
		factory: func(options singtun.Options) (singtun.Tun, error) {
			nativeTun.createdWith = options
			return nativeTun, nil
		},
	}

	assembled, err := Assemble(AssembleOptions{
		Platform: "windows",
		Device: DeviceConfig{
			Name: "amz0",
			MTU:  1400,
		},
		Config: Config{
			Device: DeviceConfig{Name: "amz0", MTU: 1400},
			Addresses: []Address{
				{CIDR: testkit.TunIPv4CIDR},
				{CIDR: testkit.TunIPv6CIDR},
			},
		},
		Routes: RoutePlan{
			Mode:           RouteModeGlobal,
			Routes:         []string{testkit.DefaultRouteV4, testkit.DefaultRouteV6},
			EndpointRoutes: []string{testkit.EndpointRouteV4Alt},
		},
		Provider: provider,
		Adapter:  NewSystemAdapter(),
	})
	if err != nil {
		t.Fatalf("expected assemble success, got %v", err)
	}
	defer assembled.Close()

	if nativeTun.startCalls != 1 {
		t.Fatalf("expected sing-tun start once, got %d", nativeTun.startCalls)
	}
	got := nativeTun.startedWith
	if !got.AutoRoute {
		t.Fatalf("expected start options to enable autoroute, got %+v", got)
	}
	if len(got.Inet4Address) == 0 || len(got.Inet6Address) == 0 {
		t.Fatalf("expected start options to include addresses, got %+v", got)
	}
}
