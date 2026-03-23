package kernel_test

import (
	"context"
	"testing"

	"github.com/skye-z/amz/kernel"
)

type stubTUNDevice struct {
	name   string
	mtu    int
	read   int
	writ   int
	closed bool
}

// 提供用于接口约束测试的最小假设备实现。
func (d *stubTUNDevice) Name() string {
	return d.name
}

// 返回测试设备的 MTU 快照。
func (d *stubTUNDevice) MTU() int {
	return d.mtu
}

// 返回预设的读取长度，便于约束接口签名。
func (d *stubTUNDevice) ReadPacket(context.Context, []byte) (int, error) {
	return d.read, nil
}

// 返回预设的写入长度，便于约束接口签名。
func (d *stubTUNDevice) WritePacket(context.Context, []byte) (int, error) {
	return d.writ, nil
}

// 记录关闭动作，便于约束关闭入口。
func (d *stubTUNDevice) Close() error {
	d.closed = true
	return nil
}

// 验证平台无关 TUN 设备接口暴露了最小必需方法。
func TestTUNDeviceInterface(t *testing.T) {
	var dev kernel.TUNDevice = &stubTUNDevice{name: "igara0", mtu: 1280, read: 4, writ: 4}

	buf := make([]byte, 4)
	if dev.Name() != "igara0" {
		t.Fatalf("expected device name, got %q", dev.Name())
	}
	if dev.MTU() != 1280 {
		t.Fatalf("expected mtu 1280, got %d", dev.MTU())
	}
	n, err := dev.ReadPacket(context.Background(), buf)
	if err != nil {
		t.Fatalf("expected read success, got %v", err)
	}
	if n != 4 {
		t.Fatalf("expected read length 4, got %d", n)
	}
	n, err = dev.WritePacket(context.Background(), buf)
	if err != nil {
		t.Fatalf("expected write success, got %v", err)
	}
	if n != 4 {
		t.Fatalf("expected write length 4, got %d", n)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
}

// 验证路由模式仅暴露全局与按需两种最小模型。
func TestRouteModes(t *testing.T) {
	if kernel.RouteModeGlobal.String() != "global" {
		t.Fatalf("expected global mode string, got %q", kernel.RouteModeGlobal.String())
	}
	if kernel.RouteModeSplit.String() != "split" {
		t.Fatalf("expected split mode string, got %q", kernel.RouteModeSplit.String())
	}
	if kernel.RouteMode("custom").Valid() {
		t.Fatal("expected custom mode to be invalid")
	}
	if !kernel.RouteModeGlobal.Valid() || !kernel.RouteModeSplit.Valid() {
		t.Fatal("expected built-in route modes to be valid")
	}
}

// 验证路由计划会复制切片，避免调用方后续修改污染管理器。
func TestRoutePlanClone(t *testing.T) {
	plan := kernel.RoutePlan{
		Mode:           kernel.RouteModeGlobal,
		DeviceName:     "igara0",
		MTU:            1280,
		LocalPrefixes:  []string{"172.16.0.2/32", "2606:4700:110:8d36::2/128"},
		Routes:         []string{"0.0.0.0/0", "::/0"},
		EndpointRoutes: []string{"162.159.198.1/32"},
	}

	clone := plan.Clone()
	plan.LocalPrefixes[0] = "mutated"
	plan.Routes[0] = "mutated"
	plan.EndpointRoutes[0] = "mutated"

	if clone.Mode != kernel.RouteModeGlobal {
		t.Fatalf("expected global mode, got %q", clone.Mode)
	}
	if clone.DeviceName != "igara0" {
		t.Fatalf("expected device name igara0, got %q", clone.DeviceName)
	}
	if clone.LocalPrefixes[0] != "172.16.0.2/32" {
		t.Fatalf("expected copied local prefix, got %q", clone.LocalPrefixes[0])
	}
	if clone.Routes[0] != "0.0.0.0/0" {
		t.Fatalf("expected copied route, got %q", clone.Routes[0])
	}
	if clone.EndpointRoutes[0] != "162.159.198.1/32" {
		t.Fatalf("expected copied endpoint route, got %q", clone.EndpointRoutes[0])
	}
}

// 验证路由管理器会保留计划快照并在应用时记录设备名。
func TestRouteManagerApply(t *testing.T) {
	manager, err := kernel.NewRouteManager(kernel.RoutePlan{
		Mode:           kernel.RouteModeSplit,
		DeviceName:     "igara0",
		MTU:            1280,
		LocalPrefixes:  []string{"172.16.0.2/32"},
		Routes:         []string{"100.64.0.0/10"},
		EndpointRoutes: []string{"162.159.198.1/32"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	dev := &stubTUNDevice{name: "igara0", mtu: 1280}
	if err := manager.Apply(context.Background(), dev); err != nil {
		t.Fatalf("expected apply success, got %v", err)
	}

	snapshot := manager.Snapshot()
	if snapshot.Mode != kernel.RouteModeSplit {
		t.Fatalf("expected split mode, got %q", snapshot.Mode)
	}
	if snapshot.DeviceName != "igara0" {
		t.Fatalf("expected planned device name, got %q", snapshot.DeviceName)
	}
	if snapshot.BoundDevice != "igara0" {
		t.Fatalf("expected bound device name, got %q", snapshot.BoundDevice)
	}
	if !snapshot.Applied {
		t.Fatal("expected manager to be marked applied")
	}
	if len(snapshot.Routes) != 1 || snapshot.Routes[0] != "100.64.0.0/10" {
		t.Fatalf("unexpected route snapshot: %+v", snapshot.Routes)
	}
	if err := manager.Reset(context.Background()); err != nil {
		t.Fatalf("expected reset success, got %v", err)
	}
	if manager.Snapshot().Applied {
		t.Fatal("expected manager to be reset")
	}
}

// 验证路由管理器会拒绝无效计划与空设备入口。
func TestRouteManagerRejectsInvalidInput(t *testing.T) {
	if _, err := kernel.NewRouteManager(kernel.RoutePlan{}); err == nil {
		t.Fatal("expected invalid route plan error")
	}

	manager, err := kernel.NewRouteManager(kernel.RoutePlan{
		Mode:           kernel.RouteModeGlobal,
		DeviceName:     "igara0",
		MTU:            1280,
		LocalPrefixes:  []string{"172.16.0.2/32"},
		Routes:         []string{"0.0.0.0/0"},
		EndpointRoutes: []string{"162.159.198.1/32"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := manager.Apply(context.Background(), nil); err == nil {
		t.Fatal("expected nil device error")
	}
}
