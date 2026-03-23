package tun_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/skye-z/amz/internal/tun"
)

// 验证平台 provider 选择入口会返回对应平台的占位实现。
func TestSelectProviderByPlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		goos     string
		wantName string
		wantFake bool
	}{
		{name: "linux", goos: "linux", wantName: "linux", wantFake: true},
		{name: "darwin", goos: "darwin", wantName: "darwin", wantFake: true},
		{name: "windows", goos: "windows", wantName: "windows", wantFake: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			provider, err := tun.NewProviderForOS(tt.goos)
			if err != nil {
				t.Fatalf("expected select success, got %v", err)
			}
			if provider.Platform() != tt.wantName {
				t.Fatalf("expected platform %q, got %q", tt.wantName, provider.Platform())
			}
			if provider.IsFake() != tt.wantFake {
				t.Fatalf("expected fake %v, got %v", tt.wantFake, provider.IsFake())
			}

			dev, err := provider.Open(context.Background(), tun.DeviceConfig{Name: "amz0", MTU: 1400})
			if err != nil {
				t.Fatalf("expected open success, got %v", err)
			}
			if dev.Name() != "amz0" {
				t.Fatalf("expected device name amz0, got %q", dev.Name())
			}
			if dev.MTU() != 1400 {
				t.Fatalf("expected mtu 1400, got %d", dev.MTU())
			}
		})
	}
}

// 验证当前平台入口与非法平台分支都具备稳定行为。
func TestNewProvider(t *testing.T) {
	t.Parallel()

	provider, err := tun.NewProvider()
	if err != nil {
		t.Fatalf("expected current platform provider, got %v", err)
	}
	if provider.Platform() != runtime.GOOS {
		t.Fatalf("expected platform %q, got %q", runtime.GOOS, provider.Platform())
	}
	if !provider.IsFake() {
		t.Fatal("expected current platform provider to be fake placeholder")
	}

	if _, err := tun.NewProviderForOS("plan9"); err == nil {
		t.Fatal("expected unsupported platform error")
	}
	if got := tun.PlatformName("linux"); got != "linux" {
		t.Fatalf("expected linux platform name, got %q", got)
	}
}

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

// 验证高权限需求、安全警告与失败回滚骨架会产出稳定快照。
func TestProtectionPlanSnapshotIsolation(t *testing.T) {
	t.Parallel()

	plan := tun.ProtectionPlan{
		Requirement: tun.PrivilegeRequirement{
			Level:      tun.PrivilegeLevelElevated,
			Reason:     "configure tun routes",
			Operations: []string{"create-device", "apply-routes"},
		},
		Warnings: []tun.SecurityWarning{
			{
				Code:       "route-change",
				Summary:    "default route will change",
				Mitigation: "confirm physical uplink remains reachable",
			},
		},
		Rollback: []tun.RollbackStep{
			{
				Stage:  "routes",
				Action: "restore previous routes snapshot",
			},
		},
	}

	if err := plan.Validate(); err != nil {
		t.Fatalf("expected valid protection plan, got %v", err)
	}

	snapshot := plan.Clone()
	if snapshot.Requirement.Level != tun.PrivilegeLevelElevated {
		t.Fatalf("expected elevated requirement, got %q", snapshot.Requirement.Level)
	}
	if len(snapshot.Requirement.Operations) != 2 {
		t.Fatalf("expected two operations, got %d", len(snapshot.Requirement.Operations))
	}
	if len(snapshot.Warnings) != 1 || snapshot.Warnings[0].Code != "route-change" {
		t.Fatalf("unexpected warning snapshot: %+v", snapshot.Warnings)
	}
	if len(snapshot.Rollback) != 1 || snapshot.Rollback[0].Action != "restore previous routes snapshot" {
		t.Fatalf("unexpected rollback snapshot: %+v", snapshot.Rollback)
	}

	cloned := snapshot
	plan.Requirement.Operations[0] = "mutated"
	plan.Warnings[0].Code = "mutated"
	plan.Rollback[0].Action = "mutated"
	if cloned.Requirement.Operations[0] != "create-device" {
		t.Fatalf("expected requirement isolation, got %+v", cloned.Requirement.Operations)
	}
	if cloned.Warnings[0].Code != "route-change" {
		t.Fatalf("expected warning isolation, got %+v", cloned.Warnings)
	}
	if cloned.Rollback[0].Action != "restore previous routes snapshot" {
		t.Fatalf("expected rollback isolation, got %+v", cloned.Rollback)
	}
}

// 验证失败恢复入口只生成恢复建议，不执行真实系统调用。
func TestRecoverFailureReturnsGuidance(t *testing.T) {
	t.Parallel()

	recovery := tun.NewFailureRecovery(tun.ProtectionPlan{
		Requirement: tun.PrivilegeRequirement{
			Level:      tun.PrivilegeLevelElevated,
			Reason:     "configure tun routes",
			Operations: []string{"create-device", "apply-routes"},
		},
		Warnings: []tun.SecurityWarning{
			{
				Code:       "admin-needed",
				Summary:    "privileged operations may fail without elevation",
				Mitigation: "rerun with appropriate privileges after confirmation",
			},
		},
		Rollback: []tun.RollbackStep{
			{
				Stage:  "device",
				Action: "close placeholder device handle",
			},
			{
				Stage:  "routes",
				Action: "restore previous routes snapshot",
			},
		},
	})

	result, err := recovery.Recover(tun.FailureEvent{
		Stage: "apply-routes",
		Err:   context.DeadlineExceeded,
	})
	if err != nil {
		t.Fatalf("expected recover success, got %v", err)
	}
	if result.Stage != "apply-routes" {
		t.Fatalf("expected stage apply-routes, got %q", result.Stage)
	}
	if result.Cause != context.DeadlineExceeded.Error() {
		t.Fatalf("expected cause %q, got %q", context.DeadlineExceeded.Error(), result.Cause)
	}
	if !result.RollbackRequired {
		t.Fatal("expected rollback required")
	}
	if len(result.Rollback) != 2 {
		t.Fatalf("expected two rollback steps, got %d", len(result.Rollback))
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "admin-needed" {
		t.Fatalf("unexpected warnings: %+v", result.Warnings)
	}
	if result.UserHint == "" {
		t.Fatal("expected non-empty user hint")
	}

	result.Rollback[0].Action = "mutated"
	result.Warnings[0].Code = "mutated"
	second, err := recovery.Recover(tun.FailureEvent{Stage: "apply-routes", Err: context.Canceled})
	if err != nil {
		t.Fatalf("expected second recover success, got %v", err)
	}
	if second.Rollback[0].Action != "close placeholder device handle" {
		t.Fatalf("expected rollback isolation, got %+v", second.Rollback)
	}
	if second.Warnings[0].Code != "admin-needed" {
		t.Fatalf("expected warning isolation, got %+v", second.Warnings)
	}

	if _, err := recovery.Recover(tun.FailureEvent{}); err == nil {
		t.Fatal("expected invalid failure event")
	}
	if _, err := tun.NewFailureRecovery(tun.ProtectionPlan{}).Recover(tun.FailureEvent{Stage: "x", Err: context.Canceled}); err == nil {
		t.Fatal("expected invalid protection plan")
	}
	if err := (tun.PrivilegeRequirement{}).Validate(); err == nil {
		t.Fatal("expected invalid privilege requirement")
	}
	if err := (tun.SecurityWarning{}).Validate(); err == nil {
		t.Fatal("expected invalid security warning")
	}
	if err := (tun.RollbackStep{}).Validate(); err == nil {
		t.Fatal("expected invalid rollback step")
	}
	if err := (tun.ProtectionPlan{}).Validate(); err == nil {
		t.Fatal("expected invalid protection plan")
	}
}
