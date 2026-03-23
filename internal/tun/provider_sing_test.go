package tun

import (
	"errors"
	"io"
	"net/netip"
	"testing"

	singtun "github.com/sagernet/sing-tun"
)

type fakeNativeTun struct {
	options      []singtun.Options
	failUpdateAt int
}

func (f *fakeNativeTun) Read([]byte) (int, error)    { return 0, io.EOF }
func (f *fakeNativeTun) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeNativeTun) Name() (string, error)       { return "amz0", nil }
func (f *fakeNativeTun) Start() error                { return nil }
func (f *fakeNativeTun) Close() error                { return nil }
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
		tun:  nativeTun,
		name: "amz0",
		mtu:  1400,
		options: singtun.Options{
			Name:      "amz0",
			MTU:       1400,
			AutoRoute: false,
		},
	}

	if err := device.ApplyTUNConfig(Config{
		Device: DeviceConfig{Name: "amz0", MTU: 1400},
		Addresses: []Address{
			{CIDR: "172.16.0.2/32"},
			{CIDR: "2606:4700:110:8d36::2/128"},
		},
	}); err != nil {
		t.Fatalf("expected apply config success, got %v", err)
	}
	if err := device.ApplyTUNRoutes(RoutePlan{
		Mode:           RouteModeSplit,
		Routes:         []string{"100.64.0.0/10", "2606:4700::/64"},
		EndpointRoutes: []string{"162.159.198.1/32", "2606:4700:d0::a29f:c001/128"},
	}); err != nil {
		t.Fatalf("expected apply routes success, got %v", err)
	}

	if len(nativeTun.options) != 2 {
		t.Fatalf("expected config and route updates, got %d", len(nativeTun.options))
	}
	got := nativeTun.options[1]
	if got.AutoRoute {
		t.Fatalf("expected split mode to keep autoroute disabled, got %+v", got)
	}
	if len(got.Inet4Address) != 1 || got.Inet4Address[0] != netip.MustParsePrefix("172.16.0.2/32") {
		t.Fatalf("unexpected inet4 address options: %+v", got.Inet4Address)
	}
	if len(got.Inet6Address) != 1 || got.Inet6Address[0] != netip.MustParsePrefix("2606:4700:110:8d36::2/128") {
		t.Fatalf("unexpected inet6 address options: %+v", got.Inet6Address)
	}
	if len(got.Inet4RouteAddress) != 1 || got.Inet4RouteAddress[0] != netip.MustParsePrefix("100.64.0.0/10") {
		t.Fatalf("unexpected inet4 route options: %+v", got.Inet4RouteAddress)
	}
	if len(got.Inet6RouteAddress) != 1 || got.Inet6RouteAddress[0] != netip.MustParsePrefix("2606:4700::/64") {
		t.Fatalf("unexpected inet6 route options: %+v", got.Inet6RouteAddress)
	}
	if len(got.Inet4RouteExcludeAddress) != 1 || got.Inet4RouteExcludeAddress[0] != netip.MustParsePrefix("162.159.198.1/32") {
		t.Fatalf("unexpected inet4 route exclude options: %+v", got.Inet4RouteExcludeAddress)
	}
	if len(got.Inet6RouteExcludeAddress) != 1 || got.Inet6RouteExcludeAddress[0] != netip.MustParsePrefix("2606:4700:d0::a29f:c001/128") {
		t.Fatalf("unexpected inet6 route exclude options: %+v", got.Inet6RouteExcludeAddress)
	}
}

// 验证 sing-tun 设备会在路由更新失败时执行回滚。
func TestSingDeviceApplyTUNRoutesRollbackOnFailure(t *testing.T) {
	nativeTun := &fakeNativeTun{failUpdateAt: 2}
	device := &singDevice{
		tun:  nativeTun,
		name: "amz0",
		mtu:  1400,
		options: singtun.Options{
			Name:      "amz0",
			MTU:       1400,
			AutoRoute: false,
		},
	}

	if err := device.ApplyTUNConfig(Config{
		Device: DeviceConfig{Name: "amz0", MTU: 1400},
		Addresses: []Address{
			{CIDR: "172.16.0.2/32"},
		},
	}); err != nil {
		t.Fatalf("expected apply config success, got %v", err)
	}

	err := device.ApplyTUNRoutes(RoutePlan{
		Mode:           RouteModeGlobal,
		Routes:         []string{"0.0.0.0/0", "::/0"},
		EndpointRoutes: []string{"162.159.198.1/32", "2606:4700:d0::a29f:c001/128"},
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
