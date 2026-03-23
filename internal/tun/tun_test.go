package tun_test

import (
	"context"
	"testing"

	"github.com/skye-z/amz/internal/tun"
)

// 验证假 provider 会校验输入并返回可收发的内存设备。
func TestFakeProviderOpenDevice(t *testing.T) {
	provider := tun.NewFakeProvider()

	dev, err := provider.Open(context.Background(), tun.DeviceConfig{
		Name: "amz0",
		MTU:  1400,
	})
	if err != nil {
		t.Fatalf("expected open success, got %v", err)
	}
	if provider.OpenCount() != 1 {
		t.Fatalf("expected one open call, got %d", provider.OpenCount())
	}
	if dev.Name() != "amz0" {
		t.Fatalf("expected device name amz0, got %q", dev.Name())
	}
	if dev.MTU() != 1400 {
		t.Fatalf("expected mtu 1400, got %d", dev.MTU())
	}

	inbound := []byte{0x45, 0x00, 0x00, 0x14}
	if err := dev.InjectInbound(inbound); err != nil {
		t.Fatalf("expected inject success, got %v", err)
	}

	buf := make([]byte, 32)
	n, err := dev.ReadPacket(context.Background(), buf)
	if err != nil {
		t.Fatalf("expected read success, got %v", err)
	}
	if n != len(inbound) {
		t.Fatalf("expected read length %d, got %d", len(inbound), n)
	}
	if string(buf[:n]) != string(inbound) {
		t.Fatalf("expected inbound packet %v, got %v", inbound, buf[:n])
	}

	outbound := []byte{0x60, 0x00, 0x00, 0x00}
	n, err = dev.WritePacket(context.Background(), outbound)
	if err != nil {
		t.Fatalf("expected write success, got %v", err)
	}
	if n != len(outbound) {
		t.Fatalf("expected write length %d, got %d", len(outbound), n)
	}
	if len(dev.WrittenPackets()) != 1 {
		t.Fatalf("expected one written packet, got %d", len(dev.WrittenPackets()))
	}

	if _, err := provider.Open(context.Background(), tun.DeviceConfig{}); err == nil {
		t.Fatal("expected invalid device config error")
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("expected provider close success, got %v", err)
	}
}

// 验证假 adapter 只记录平台无关配置与路由快照。
func TestFakeAdapterApplySnapshot(t *testing.T) {
	provider := tun.NewFakeProvider()
	dev, err := provider.Open(context.Background(), tun.DeviceConfig{
		Name: "amz0",
		MTU:  1280,
	})
	if err != nil {
		t.Fatalf("expected open success, got %v", err)
	}

	adapter := tun.NewFakeAdapter()
	config := tun.Config{
		Device: tun.DeviceConfig{Name: "amz0", MTU: 1280},
		Addresses: []tun.Address{
			{CIDR: "172.16.0.2/32"},
			{CIDR: "2606:4700:110:8d36::2/128"},
		},
	}
	routes := tun.RoutePlan{
		Mode:           tun.RouteModeSplit,
		Routes:         []string{"100.64.0.0/10"},
		EndpointRoutes: []string{"162.159.198.1/32"},
	}

	if err := adapter.ApplyConfig(context.Background(), dev, config); err != nil {
		t.Fatalf("expected apply config success, got %v", err)
	}
	if err := adapter.ApplyRoutes(context.Background(), dev, routes); err != nil {
		t.Fatalf("expected apply routes success, got %v", err)
	}

	snapshot := adapter.Snapshot()
	if !snapshot.ConfigApplied || !snapshot.RoutesApplied {
		t.Fatalf("expected both apply flags true, got %+v", snapshot)
	}
	if snapshot.BoundDevice != "amz0" {
		t.Fatalf("expected bound device amz0, got %q", snapshot.BoundDevice)
	}
	if len(snapshot.Config.Addresses) != 2 {
		t.Fatalf("expected two addresses, got %d", len(snapshot.Config.Addresses))
	}
	if len(snapshot.Routes.Routes) != 1 || snapshot.Routes.Routes[0] != "100.64.0.0/10" {
		t.Fatalf("unexpected route snapshot: %+v", snapshot.Routes)
	}

	config.Addresses[0].CIDR = "mutated"
	routes.Routes[0] = "mutated"
	snapshot = adapter.Snapshot()
	if snapshot.Config.Addresses[0].CIDR != "172.16.0.2/32" {
		t.Fatalf("expected config snapshot isolation, got %+v", snapshot.Config.Addresses)
	}
	if snapshot.Routes.Routes[0] != "100.64.0.0/10" {
		t.Fatalf("expected route snapshot isolation, got %+v", snapshot.Routes.Routes)
	}

	if err := adapter.Reset(context.Background()); err != nil {
		t.Fatalf("expected reset success, got %v", err)
	}
	reset := adapter.Snapshot()
	if reset.ConfigApplied || reset.RoutesApplied || reset.BoundDevice != "" {
		t.Fatalf("expected cleared snapshot, got %+v", reset)
	}

	if err := adapter.ApplyConfig(context.Background(), nil, config); err == nil {
		t.Fatal("expected nil device config error")
	}
	if err := adapter.ApplyRoutes(context.Background(), dev, tun.RoutePlan{}); err == nil {
		t.Fatal("expected invalid route plan error")
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("expected device close success, got %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("expected provider close success, got %v", err)
	}
}

// 验证最小平台无关模型会拒绝缺失关键字段的输入。
func TestValidatePlatformNeutralModels(t *testing.T) {
	validConfig := tun.Config{
		Device: tun.DeviceConfig{Name: "amz0", MTU: 1280},
		Addresses: []tun.Address{
			{CIDR: "172.16.0.2/32"},
		},
	}
	if err := validConfig.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	validPlan := tun.RoutePlan{
		Mode:           tun.RouteModeGlobal,
		Routes:         []string{"0.0.0.0/0", "::/0"},
		EndpointRoutes: []string{"162.159.198.1/32"},
	}
	if err := validPlan.Validate(); err != nil {
		t.Fatalf("expected valid route plan, got %v", err)
	}

	if err := (tun.DeviceConfig{}).Validate(); err == nil {
		t.Fatal("expected invalid device config")
	}
	if err := (tun.Address{}).Validate(); err == nil {
		t.Fatal("expected invalid address")
	}
	if err := (tun.Config{}).Validate(); err == nil {
		t.Fatal("expected invalid config")
	}
	if err := (tun.RoutePlan{}).Validate(); err == nil {
		t.Fatal("expected invalid route plan")
	}
	if tun.RouteMode("custom").Valid() {
		t.Fatal("expected custom route mode invalid")
	}
}
