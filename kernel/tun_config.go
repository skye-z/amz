package kernel

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"

	"github.com/skye-z/amz/types"
)

// 描述平台无关的最小 TUN 设备参数。
type TUNDeviceConfig struct {
	Name string
	MTU  int
}

// 检查设备参数是否满足最小骨架要求。
func (c TUNDeviceConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: tun name is required", types.ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", types.ErrInvalidConfig)
	}
	return nil

}

// 描述需要配置到假设备上的单个地址前缀。
type TUNAddress struct {
	CIDR string
}

// 检查地址前缀是否为非空且可解析的 CIDR。
func (a TUNAddress) Validate() error {
	if strings.TrimSpace(a.CIDR) == "" {
		return fmt.Errorf("%w: address cidr is required", types.ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(a.CIDR); err != nil {
		return fmt.Errorf("%w: invalid address cidr: %v", types.ErrInvalidConfig, err)
	}
	return nil
}

// 描述平台无关的最小地址与 MTU 配置集合。
type TUNConfiguration struct {
	Device    TUNDeviceConfig
	Addresses []TUNAddress
}

// 返回配置副本，避免调用方后续修改影响内部状态。
func (c TUNConfiguration) Clone() TUNConfiguration {
	clone := TUNConfiguration{
		Device:    c.Device,
		Addresses: make([]TUNAddress, len(c.Addresses)),
	}
	copy(clone.Addresses, c.Addresses)
	return clone
}

// 检查配置是否具备最小设备参数与地址集合。
func (c TUNConfiguration) Validate() error {
	if err := c.Device.Validate(); err != nil {
		return err
	}
	if len(c.Addresses) == 0 {
		return fmt.Errorf("%w: tun addresses are required", types.ErrInvalidConfig)
	}
	for _, addr := range c.Addresses {
		if err := addr.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// 提供仅用于测试与骨架联调的内存假设备。
type FakeTUNDevice struct {
	mu      sync.Mutex
	name    string
	mtu     int
	inbound [][]byte
	written [][]byte
	closed  bool
}

// 创建一个不触发真实系统调用的 TUN 假设备。
func NewFakeTUNDevice(cfg TUNDeviceConfig) (*FakeTUNDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &FakeTUNDevice{
		name: cfg.Name,
		mtu:  cfg.MTU,
	}, nil
}

// 返回假设备名称，便于绑定配置与快照。
func (d *FakeTUNDevice) Name() string {
	return d.name
}

// 返回假设备 MTU，便于上层读取配置结果。
func (d *FakeTUNDevice) MTU() int {
	return d.mtu
}

// 向读取队列注入一份数据包副本。
func (d *FakeTUNDevice) InjectInbound(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	buf := append([]byte(nil), packet...)
	d.inbound = append(d.inbound, buf)
	return nil
}

// 从读取队列取出一个数据包并拷贝到目标缓冲区。
func (d *FakeTUNDevice) ReadPacket(_ context.Context, dst []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if len(d.inbound) == 0 {
		return 0, io.EOF
	}
	packet := d.inbound[0]
	d.inbound = d.inbound[1:]
	return copy(dst, packet), nil
}

// 记录写入数据包的副本，便于测试断言收发行为。
func (d *FakeTUNDevice) WritePacket(_ context.Context, packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	buf := append([]byte(nil), packet...)
	d.written = append(d.written, buf)
	return len(packet), nil
}

// 返回已写入数据包的深拷贝快照。
func (d *FakeTUNDevice) WrittenPackets() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, 0, len(d.written))
	for _, packet := range d.written {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

// 标记假设备关闭，后续收发均返回关闭错误。
func (d *FakeTUNDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// 描述配置管理器持有的最小只读快照。
type TUNConfigSnapshot struct {
	Device      TUNDeviceConfig
	Addresses   []TUNAddress
	BoundDevice string
	Applied     bool
}

// 管理平台无关的地址与 MTU 配置骨架。
type TUNConfigManager struct {
	mu          sync.Mutex
	config      TUNConfiguration
	boundDevice string
	applied     bool
}

// 创建只负责持有配置与应用状态的最小管理器。
func NewTUNConfigManager(cfg TUNConfiguration) (*TUNConfigManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &TUNConfigManager{config: cfg.Clone()}, nil
}

// 记录一次与设备绑定的配置应用，不执行真实平台调用。
func (m *TUNConfigManager) Apply(_ context.Context, dev TUNDevice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", types.ErrInvalidConfig)
	}
	m.boundDevice = dev.Name()
	m.applied = true
	return nil
}

// 清空绑定状态，便于上层复用同一配置对象。
func (m *TUNConfigManager) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.boundDevice = ""
	m.applied = false
	return nil
}

// 返回当前配置与应用状态的只读快照。
func (m *TUNConfigManager) Snapshot() TUNConfigSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := m.config.Clone()
	return TUNConfigSnapshot{
		Device:      clone.Device,
		Addresses:   clone.Addresses,
		BoundDevice: m.boundDevice,
		Applied:     m.applied,
	}
}
