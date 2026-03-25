package tun

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/skye-z/amz/internal/config"
)

// 描述平台无关的最小设备参数。
type DeviceConfig struct {
	Name string
	MTU  int
}

// 检查设备参数是否满足骨架阶段的最小约束。
func (c DeviceConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: tun name is required", config.ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", config.ErrInvalidConfig)
	}
	return nil

}

// 描述需要应用到设备上的单个地址前缀。
type Address struct {
	CIDR string
}

// 检查地址前缀是否为可解析的 CIDR。
func (a Address) Validate() error {
	cidr := strings.TrimSpace(a.CIDR)
	if cidr == "" {
		return fmt.Errorf("%w: address cidr is required", config.ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("%w: invalid address cidr: %v", config.ErrInvalidConfig, err)
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
		return fmt.Errorf("%w: tun addresses are required", config.ErrInvalidConfig)
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
		return fmt.Errorf("%w: route mode is required", config.ErrInvalidConfig)
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("%w: routes are required", config.ErrInvalidConfig)
	}
	if len(p.EndpointRoutes) == 0 {
		return fmt.Errorf("%w: endpoint routes are required", config.ErrInvalidConfig)
	}
	return nil
}

// 表示 TUN 相关操作所需的最小权限级别。
type PrivilegeLevel string

const (
	// 表示无需额外高权限的占位级别。
	PrivilegeLevelUnprivileged PrivilegeLevel = "unprivileged"
	// 表示需要管理员或 root 权限的占位级别。
	PrivilegeLevelElevated PrivilegeLevel = "elevated"
)

// 检查权限级别是否属于当前支持的最小集合。
func (l PrivilegeLevel) Valid() bool {
	switch l {
	case PrivilegeLevelUnprivileged, PrivilegeLevelElevated:
		return true
	default:
		return false
	}
}

// 描述执行 TUN 相关步骤前需要声明的权限要求。
type PrivilegeRequirement struct {
	Level      PrivilegeLevel
	Reason     string
	Operations []string
}

// 返回权限要求副本，避免外部切片修改污染内部状态。
func (r PrivilegeRequirement) Clone() PrivilegeRequirement {
	return PrivilegeRequirement{
		Level:      r.Level,
		Reason:     r.Reason,
		Operations: append([]string(nil), r.Operations...),
	}
}

// 检查权限要求是否具备最小描述信息。
func (r PrivilegeRequirement) Validate() error {
	if !r.Level.Valid() {
		return fmt.Errorf("%w: privilege level is required", config.ErrInvalidConfig)
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("%w: privilege reason is required", config.ErrInvalidConfig)
	}
	if len(r.Operations) == 0 {
		return fmt.Errorf("%w: privilege operations are required", config.ErrInvalidConfig)
	}
	for _, operation := range r.Operations {
		if strings.TrimSpace(operation) == "" {
			return fmt.Errorf("%w: privilege operation is required", config.ErrInvalidConfig)
		}
	}
	return nil
}

// 描述需要暴露给上层的安全提示。
type SecurityWarning struct {
	Code       string
	Summary    string
	Mitigation string
}

// 检查安全提示是否具备最小展示信息。
func (w SecurityWarning) Validate() error {
	if strings.TrimSpace(w.Code) == "" {
		return fmt.Errorf("%w: warning code is required", config.ErrInvalidConfig)
	}
	if strings.TrimSpace(w.Summary) == "" {
		return fmt.Errorf("%w: warning summary is required", config.ErrInvalidConfig)
	}
	if strings.TrimSpace(w.Mitigation) == "" {
		return fmt.Errorf("%w: warning mitigation is required", config.ErrInvalidConfig)
	}
	return nil
}

// 描述失败后建议执行的单个回滚动作。
type RollbackStep struct {
	Stage  string
	Action string
}

// 检查回滚动作是否具备最小描述信息。
func (s RollbackStep) Validate() error {
	if strings.TrimSpace(s.Stage) == "" {
		return fmt.Errorf("%w: rollback stage is required", config.ErrInvalidConfig)
	}
	if strings.TrimSpace(s.Action) == "" {
		return fmt.Errorf("%w: rollback action is required", config.ErrInvalidConfig)
	}
	return nil
}

// 描述 TUN 高权限、安全警告与回滚建议的骨架计划。
type ProtectionPlan struct {
	Requirement PrivilegeRequirement
	Warnings    []SecurityWarning
	Rollback    []RollbackStep
}

// 返回保护计划副本，避免外部切片修改污染内部状态。
func (p ProtectionPlan) Clone() ProtectionPlan {
	warnings := make([]SecurityWarning, len(p.Warnings))
	copy(warnings, p.Warnings)
	rollback := make([]RollbackStep, len(p.Rollback))
	copy(rollback, p.Rollback)
	return ProtectionPlan{
		Requirement: p.Requirement.Clone(),
		Warnings:    warnings,
		Rollback:    rollback,
	}
}

// 检查保护计划是否具备权限说明、警告与回滚步骤。
func (p ProtectionPlan) Validate() error {
	if err := p.Requirement.Validate(); err != nil {
		return err
	}
	if len(p.Warnings) == 0 {
		return fmt.Errorf("%w: security warnings are required", config.ErrInvalidConfig)
	}
	for _, warning := range p.Warnings {
		if err := warning.Validate(); err != nil {
			return err
		}
	}
	if len(p.Rollback) == 0 {
		return fmt.Errorf("%w: rollback steps are required", config.ErrInvalidConfig)
	}
	for _, step := range p.Rollback {
		if err := step.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// 描述一次失败恢复入口收到的最小失败信息。
type FailureEvent struct {
	Stage string
	Err   error
}

// 检查失败信息是否具备最小上下文。
func (e FailureEvent) Validate() error {
	if strings.TrimSpace(e.Stage) == "" {
		return fmt.Errorf("%w: failure stage is required", config.ErrInvalidConfig)
	}
	if e.Err == nil {
		return fmt.Errorf("%w: failure error is required", config.ErrInvalidConfig)
	}
	return nil
}

// 描述失败恢复入口返回给上层的只读建议结果。
type RecoveryResult struct {
	Stage            string
	Cause            string
	Rollback         []RollbackStep
	Warnings         []SecurityWarning
	RollbackRequired bool
	UserHint         string
}

// 负责根据静态保护计划生成失败恢复建议。
type FailureRecovery struct {
	plan ProtectionPlan
}

// 创建一个仅生成恢复建议、不执行真实系统调用的恢复器。
func NewFailureRecovery(plan ProtectionPlan) *FailureRecovery {
	return &FailureRecovery{plan: plan.Clone()}
}

// 根据失败事件返回回滚建议与安全提示。
func (r *FailureRecovery) Recover(event FailureEvent) (RecoveryResult, error) {
	if err := r.plan.Validate(); err != nil {
		return RecoveryResult{}, err
	}
	if err := event.Validate(); err != nil {
		return RecoveryResult{}, err
	}
	plan := r.plan.Clone()
	warnings := make([]SecurityWarning, len(plan.Warnings))
	copy(warnings, plan.Warnings)
	rollback := make([]RollbackStep, len(plan.Rollback))
	copy(rollback, plan.Rollback)
	return RecoveryResult{
		Stage:            event.Stage,
		Cause:            event.Err.Error(),
		Rollback:         rollback,
		Warnings:         warnings,
		RollbackRequired: len(rollback) > 0,
		UserHint:         fmt.Sprintf("stage %s failed; review warnings and apply rollback guidance before retrying with %s privileges", event.Stage, plan.Requirement.Level),
	}, nil
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
	Open(context.Context, DeviceConfig) (Device, error)
	Close() error
}

// 约定平台差异隔离层的最小配置适配入口。
type Adapter interface {
	ApplyConfig(context.Context, Device, Config) error
	ApplyRoutes(context.Context, Device, RoutePlan) error
	Reset(context.Context) error
	Snapshot() Snapshot
	PlaceholderError() error
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
	devices   []Device
	openCount int
	closed    bool
}

// 创建一个不会触发真实系统调用的假 provider。
func NewFakeProvider() *FakeProvider {
	return &FakeProvider{}
}

// 打开一个内存假设备，并记录调用次数。
func (p *FakeProvider) Open(_ context.Context, cfg DeviceConfig) (Device, error) {
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

// 提供接入真实 sing-tun 地址配置的最小 adapter。
type SystemAdapter struct {
	mu            sync.Mutex
	config        Config
	routes        RoutePlan
	boundDevice   string
	routeDevice   systemRouteConfigurableDevice
	configApplied bool
	routesApplied bool
}

// 创建真实系统配置 adapter。
func NewSystemAdapter() *SystemAdapter {
	return &SystemAdapter{}
}

// 真实地址配置路径已接入，不再暴露 placeholder 信号。
func (a *SystemAdapter) PlaceholderError() error {
	return nil
}

// 通过真实设备能力应用地址与 MTU 配置。
func (a *SystemAdapter) ApplyConfig(_ context.Context, dev Device, cfg Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	configurable, ok := dev.(systemConfigurableDevice)
	if !ok {
		return fmt.Errorf("%w: tun device does not support system config", config.ErrInvalidConfig)
	}
	if err := configurable.ApplyTUNConfig(cfg); err != nil {
		return err
	}
	a.config = cfg.Clone()
	a.boundDevice = dev.Name()
	a.configApplied = true
	return nil
}

// 当前阶段仅记录路由快照，真实系统路由修改将在后续能力中接入。
func (a *SystemAdapter) ApplyRoutes(_ context.Context, dev Device, plan RoutePlan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	routeConfigurable, ok := dev.(systemRouteConfigurableDevice)
	if !ok {
		return fmt.Errorf("%w: tun device does not support system routes", config.ErrInvalidConfig)
	}
	if err := routeConfigurable.ApplyTUNRoutes(plan); err != nil {
		return err
	}
	a.routes = plan.Clone()
	a.boundDevice = dev.Name()
	a.routeDevice = routeConfigurable
	a.routesApplied = true
	return nil
}

// 清空已记录的绑定状态与应用标记。
func (a *SystemAdapter) Reset(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.routeDevice != nil {
		if err := a.routeDevice.ResetTUNRoutes(); err != nil {
			return err
		}
	}
	a.config = Config{}
	a.routes = RoutePlan{}
	a.boundDevice = ""
	a.routeDevice = nil
	a.configApplied = false
	a.routesApplied = false
	return nil
}

// 返回当前配置与路由状态的只读快照。
func (a *SystemAdapter) Snapshot() Snapshot {
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

// 创建一个只记录快照、不触发真实系统调用的假 adapter。
func NewFakeAdapter() *FakeAdapter {
	return &FakeAdapter{}
}

// 返回当前 adapter 仍为占位实现的结构化错误。
func (a *FakeAdapter) PlaceholderError() error {
	return &PlaceholderError{
		Platform:  runtime.GOOS,
		Component: "adapter",
	}
}

// 记录一次配置应用，不执行真实平台调用。
func (a *FakeAdapter) ApplyConfig(_ context.Context, dev Device, cfg Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
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
		return fmt.Errorf("%w: tun device is required", config.ErrInvalidConfig)
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
