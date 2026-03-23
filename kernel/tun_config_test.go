package kernel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/types"
)

// 验证假 TUN 设备可以按队列顺序读取注入的数据包并拷贝写入数据。
func TestFakeTUNDevicePacketFlow(t *testing.T) {
	dev, err := kernel.NewFakeTUNDevice(kernel.TUNDeviceConfig{
		Name: "igara0",
		MTU:  1400,
	})
	if err != nil {
		t.Fatalf("expected fake tun device, got %v", err)
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
		t.Fatalf("expected copied inbound packet %v, got %v", inbound, buf[:n])
	}

	buf[0] = 0x99
	if string(inbound) != string([]byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("expected source packet unchanged, got %v", inbound)
	}

	outbound := []byte{0x60, 0x00, 0x00, 0x00}
	n, err = dev.WritePacket(context.Background(), outbound)
	if err != nil {
		t.Fatalf("expected write success, got %v", err)
	}
	if n != len(outbound) {
		t.Fatalf("expected write length %d, got %d", len(outbound), n)
	}

	writes := dev.WrittenPackets()
	if len(writes) != 1 {
		t.Fatalf("expected one written packet, got %d", len(writes))
	}
	if string(writes[0]) != string(outbound) {
		t.Fatalf("expected outbound packet %v, got %v", outbound, writes[0])
	}

	outbound[0] = 0x01
	if writes[0][0] != 0x60 {
		t.Fatalf("expected written packet snapshot to stay immutable, got %v", writes[0])
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
}

// 验证地址与 MTU 配置模型会拒绝缺失关键字段的输入。
func TestTUNConfigurationValidate(t *testing.T) {
	valid := kernel.TUNConfiguration{
		Device: kernel.TUNDeviceConfig{
			Name: "igara0",
			MTU:  1280,
		},
		Addresses: []kernel.TUNAddress{
			{CIDR: "172.16.0.2/32"},
			{CIDR: "2606:4700:110:8d36::2/128"},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid configuration, got %v", err)
	}

	tests := []struct {
		name string
		cfg  kernel.TUNConfiguration
	}{
		{
			name: "missing device name",
			cfg: kernel.TUNConfiguration{
				Device:    kernel.TUNDeviceConfig{MTU: 1280},
				Addresses: []kernel.TUNAddress{{CIDR: "172.16.0.2/32"}},
			},
		},
		{
			name: "mtu too small",
			cfg: kernel.TUNConfiguration{
				Device:    kernel.TUNDeviceConfig{Name: "igara0", MTU: 1200},
				Addresses: []kernel.TUNAddress{{CIDR: "172.16.0.2/32"}},
			},
		},
		{
			name: "missing addresses",
			cfg: kernel.TUNConfiguration{
				Device: kernel.TUNDeviceConfig{Name: "igara0", MTU: 1280},
			},
		},
		{
			name: "blank cidr",
			cfg: kernel.TUNConfiguration{
				Device:    kernel.TUNDeviceConfig{Name: "igara0", MTU: 1280},
				Addresses: []kernel.TUNAddress{{CIDR: "  "}},
			},
		},
		{
			name: "invalid cidr",
			cfg: kernel.TUNConfiguration{
				Device:    kernel.TUNDeviceConfig{Name: "igara0", MTU: 1280},
				Addresses: []kernel.TUNAddress{{CIDR: "not-a-cidr"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

// 验证地址前缀校验会处理协议前缀解析与错误分支。
func TestTUNAddressValidateTableDriven(t *testing.T) {
	tests := []struct {
		name    string
		addr    kernel.TUNAddress
		wantErr bool
	}{
		{
			name: "trim ipv4 cidr",
			addr: kernel.TUNAddress{CIDR: " 172.16.0.2/32\t"},
		},
		{
			name: "trim ipv6 cidr",
			addr: kernel.TUNAddress{CIDR: "\n2606:4700:110:8d36::2/128 "},
		},
		{
			name:    "reject malformed cidr",
			addr:    kernel.TUNAddress{CIDR: "172.16.0.2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.addr.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				if !errors.Is(err, types.ErrInvalidConfig) {
					t.Fatalf("expected ErrInvalidConfig, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

// 验证配置管理器只记录配置快照与应用状态，不触发真实系统调用。
func TestTUNConfigManagerApplyAndReset(t *testing.T) {
	cfg := kernel.TUNConfiguration{
		Device: kernel.TUNDeviceConfig{
			Name: "igara0",
			MTU:  1280,
		},
		Addresses: []kernel.TUNAddress{
			{CIDR: "172.16.0.2/32"},
			{CIDR: "2606:4700:110:8d36::2/128"},
		},
	}

	mgr, err := kernel.NewTUNConfigManager(cfg)
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	dev, err := kernel.NewFakeTUNDevice(cfg.Device)
	if err != nil {
		t.Fatalf("expected fake tun device, got %v", err)
	}
	if err := mgr.Apply(context.Background(), dev); err != nil {
		t.Fatalf("expected apply success, got %v", err)
	}

	snapshot := mgr.Snapshot()
	if !snapshot.Applied {
		t.Fatal("expected applied snapshot")
	}
	if snapshot.BoundDevice != "igara0" {
		t.Fatalf("expected bound device igara0, got %q", snapshot.BoundDevice)
	}
	if snapshot.Device.Name != "igara0" || snapshot.Device.MTU != 1280 {
		t.Fatalf("unexpected device snapshot: %+v", snapshot.Device)
	}
	if len(snapshot.Addresses) != 2 {
		t.Fatalf("expected two addresses, got %d", len(snapshot.Addresses))
	}

	cfg.Addresses[0].CIDR = "mutated"
	if mgr.Snapshot().Addresses[0].CIDR != "172.16.0.2/32" {
		t.Fatalf("expected manager snapshot isolation, got %+v", mgr.Snapshot().Addresses)
	}

	if err := mgr.Reset(context.Background()); err != nil {
		t.Fatalf("expected reset success, got %v", err)
	}
	if mgr.Snapshot().Applied {
		t.Fatal("expected manager to clear applied flag")
	}
	if mgr.Snapshot().BoundDevice != "" {
		t.Fatalf("expected bound device cleared, got %q", mgr.Snapshot().BoundDevice)
	}

	if err := mgr.Apply(context.Background(), nil); err == nil {
		t.Fatal("expected nil device error")
	}
	if _, err := kernel.NewTUNConfigManager(kernel.TUNConfiguration{}); err == nil {
		t.Fatal("expected invalid configuration error")
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
}
