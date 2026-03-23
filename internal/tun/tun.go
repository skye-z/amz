package tun

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"

	"github.com/skye-z/amz/types"
)

// 描述平台无关的最小设备参数。
type DeviceConfig struct {
	Name string
	MTU  int
}

// 检查设备参数是否满足骨架阶段的最小约束。
func (c DeviceConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: tun name is required", types.ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", types.ErrInvalidConfig)
	}
	return nil

}

// 描述需要应用到设备上的单个地址前缀。
type Address struct {
	CIDR string
}

// 检查地址前缀是否为可解析的 CIDR。
func (a Address) Validate() error {
	if strings.TrimSpace(a.CIDR) == "" {
		return fmt.Errorf("%w: address cidr is required", types.ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(a.CIDR); err != nil {
		return fmt.Errorf("%w: invalid address cidr: %v", types.ErrInvalidConfig, err)
	}
	return nil
}

// 描述平台无关的最小设备配置集合。
type Config struct {
	Device    DeviceConfig
	Addresses []Address
}

// 返回配置副本，避免外部切片修改污染内部状态。
func (c Config) Clone() Config {
	clone := Config{
		Device:    c.Device,
		Addresses: make([]Address, len(c.Addresses)),
	}
	copy(clone.Addresses, c.Addresses)
	return clone
}

// 检查配置是否具备最小设备参数与地址集合。
func (c Config) Validate() error {
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

// 表示路由注入的最小模式集合。
type RouteMode string

const (
	// 表示接管默认路由的全局模式。
	RouteModeGlobal RouteMode = "global"
	// 表示仅注入指定前缀的按需模式。
	RouteModeSplit RouteMode = "split"
)

// 检查模式是否属于当前支持的最小集合。
func (m RouteMode) Valid() bool {
	switch m {
	case RouteModeGlobal, RouteModeSplit:
		return true
	default:
		return false
	}
}

// 描述平台无关的最小路由计划。
type RoutePlan struct {
	Mode           RouteMode
	Routes         []string
	EndpointRoutes []string
}

// 返回计划副本，避免外部切片修改污染内部状态。
func (p RoutePlan) Clone() RoutePlan {
	return RoutePlan{
		Mode:           p.Mode,
		Routes:         append([]string(nil), p.Routes...),
		EndpointRoutes: append([]string(nil), p.EndpointRoutes...),
	}
}

// 检查路由计划是否满足骨架阶段的最小约束。
func (p RoutePlan) Validate() error {
	if !p.Mode.Valid() {
		return fmt.Errorf("%w: route mode is required", types.ErrInvalidConfig)
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("%w: routes are required", types.ErrInvalidConfig)
	}
	if len(p.EndpointRoutes) == 0 {
		return fmt.Errorf("%w: endpoint routes are required", types.ErrInvalidConfig)
	}
	return nil
}

// 约定平台无关的最小设备收发接口。
type Device interface {
	Name() string
	MTU() int
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) (int, error)
	Close() error
}

// 约定平台差异隔离层的最小设备提供入口。
type Provider interface {
	Open(context.Context, DeviceConfig) (*FakeDevice, error)
	Close() error
}

// 约定平台差异隔离层的最小配置适配入口。
type Adapter interface {
	ApplyConfig(context.Context, Device, Config) error
	ApplyRoutes(context.Context, Device, RoutePlan) error
	Reset(context.Context) error
	Snapshot() Snapshot
}

// 提供仅用于测试与骨架联调的内存假设备。
type FakeDevice struct {
	mu      sync.Mutex
	name    string
	mtu     int
	inbound [][]byte
	written [][]byte
	closed  bool
}

// 创建一个不触发真实系统调用的假设备。
func NewFakeDevice(cfg DeviceConfig) (*FakeDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &FakeDevice{name: cfg.Name, mtu: cfg.MTU}, nil
}

// 返回假设备名称，便于绑定配置与快照。
func (d *FakeDevice) Name() string {
	return d.name
}

// 返回假设备 MTU，便于上层读取配置结果。
func (d *FakeDevice) MTU() int {
	return d.mtu
}

// 向读取队列注入一份数据包副本。
func (d *FakeDevice) InjectInbound(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	d.inbound = append(d.inbound, append([]byte(nil), packet...))
	return nil
}

// 从读取队列取出一个数据包并拷贝到目标缓冲区。
func (d *FakeDevice) ReadPacket(_ context.Context, dst []byte) (int, error) {
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
func (d *FakeDevice) WritePacket(_ context.Context, packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	d.written = append(d.written, append([]byte(nil), packet...))
	return len(packet), nil
}

// 返回已写入数据包的深拷贝快照。
func (d *FakeDevice) WrittenPackets() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, 0, len(d.written))
	for _, packet := range d.written {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

// 标记假设备关闭，后续收发均返回关闭错误。
func (d *FakeDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// 提供仅用于测试与骨架联调的假 provider。
type FakeProvider struct {
	mu        sync.Mutex
	devices   []*FakeDevice
	openCount int
	closed    bool
}

// 创建一个不会触发真实系统调用的假 provider。
func NewFakeProvider() *FakeProvider {
	return &FakeProvider{}
}

// 打开一个内存假设备，并记录调用次数。
func (p *FakeProvider) Open(_ context.Context, cfg DeviceConfig) (*FakeDevice, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, io.ErrClosedPipe
	}
	dev, err := NewFakeDevice(cfg)
	if err != nil {
		return nil, err
	}
	p.devices = append(p.devices, dev)
	p.openCount++
	return dev, nil
}

// 返回打开设备的调用次数快照。
func (p *FakeProvider) OpenCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.openCount
}

// 关闭 provider，并级联关闭其创建的假设备。
func (p *FakeProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, dev := range p.devices {
		_ = dev.Close()
	}
	p.closed = true
	return nil
}

// 描述适配器持有的最小只读快照。
type Snapshot struct {
	Config        Config
	Routes        RoutePlan
	BoundDevice   string
	ConfigApplied bool
	RoutesApplied bool
}

// 提供仅用于测试与骨架联调的假 adapter。
type FakeAdapter struct {
	mu            sync.Mutex
	config        Config
	routes        RoutePlan
	boundDevice   string
	configApplied bool
	routesApplied bool
}

// 创建一个只记录快照、不触发真实系统调用的假 adapter。
func NewFakeAdapter() *FakeAdapter {
	return &FakeAdapter{}
}

// 记录一次配置应用，不执行真实平台调用。
func (a *FakeAdapter) ApplyConfig(_ context.Context, dev Device, cfg Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", types.ErrInvalidConfig)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.config = cfg.Clone()
	a.boundDevice = dev.Name()
	a.configApplied = true
	return nil
}

// 记录一次路由应用，不执行真实平台调用。
func (a *FakeAdapter) ApplyRoutes(_ context.Context, dev Device, plan RoutePlan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", types.ErrInvalidConfig)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	a.routes = plan.Clone()
	a.boundDevice = dev.Name()
	a.routesApplied = true
	return nil
}

// 清空已记录的绑定状态与应用标记。
func (a *FakeAdapter) Reset(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = Config{}
	a.routes = RoutePlan{}
	a.boundDevice = ""
	a.configApplied = false
	a.routesApplied = false
	return nil
}

// 返回当前配置与路由状态的只读快照。
func (a *FakeAdapter) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Snapshot{
		Config:        a.config.Clone(),
		Routes:        a.routes.Clone(),
		BoundDevice:   a.boundDevice,
		ConfigApplied: a.configApplied,
		RoutesApplied: a.routesApplied,
	}
}
