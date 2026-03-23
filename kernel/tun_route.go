package kernel

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/skye-z/amz/types"
)

// 约定平台无关的最小 TUN 设备收发接口。
type TUNDevice interface {
	Name() string
	MTU() int
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) (int, error)
	Close() error
}

// 表示路由注入的最小模式集合。
type RouteMode string

const (
	// 表示接管默认路由的全局模式。
	RouteModeGlobal RouteMode = "global"
	// 表示仅注入指定前缀的按需模式。
	RouteModeSplit RouteMode = "split"
)

// 返回适合快照与日志使用的字符串值。
func (m RouteMode) String() string {
	return string(m)
}

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
	DeviceName     string
	MTU            int
	LocalPrefixes  []string
	Routes         []string
	EndpointRoutes []string
}

// 返回独立切片副本，避免调用方后续修改污染内部状态。
func (p RoutePlan) Clone() RoutePlan {
	return RoutePlan{
		Mode:           p.Mode,
		DeviceName:     p.DeviceName,
		MTU:            p.MTU,
		LocalPrefixes:  append([]string(nil), p.LocalPrefixes...),
		Routes:         append([]string(nil), p.Routes...),
		EndpointRoutes: append([]string(nil), p.EndpointRoutes...),
	}
}

// 检查路由计划是否满足最小骨架约束。
func (p RoutePlan) Validate() error {
	if !p.Mode.Valid() {
		return fmt.Errorf("%w: route mode is required", types.ErrInvalidConfig)
	}
	if strings.TrimSpace(p.DeviceName) == "" {
		return fmt.Errorf("%w: device name is required", types.ErrInvalidConfig)
	}
	if p.MTU < 1280 {
		return fmt.Errorf("%w: mtu out of range", types.ErrInvalidConfig)
	}
	if len(p.LocalPrefixes) == 0 {
		return fmt.Errorf("%w: local prefixes are required", types.ErrInvalidConfig)
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("%w: routes are required", types.ErrInvalidConfig)
	}
	if len(p.EndpointRoutes) == 0 {
		return fmt.Errorf("%w: endpoint routes are required", types.ErrInvalidConfig)
	}
	return nil
}

// 描述路由管理器当前持有的最小状态快照。
type RouteSnapshot struct {
	Mode                 RouteMode
	DeviceName           string
	MTU                  int
	LocalPrefixes        []string
	Routes               []string
	EndpointRoutes       []string
	KeepaliveRoutes      []string
	DefaultRoutes        []string
	DefaultRouteInjected bool
	BoundDevice          string
	Applied              bool
}

// 管理平台无关的路由计划与应用入口。
type RouteManager struct {
	mu              sync.Mutex
	plan            RoutePlan
	keepaliveRoutes []string
	defaultRoutes   []string
	defaultInjected bool
	boundDevice     string
	applied         bool
}

// 创建仅负责保存计划与状态的最小路由管理器。
func NewRouteManager(plan RoutePlan) (*RouteManager, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return &RouteManager{plan: plan.Clone()}, nil
}

// 记录一次计划应用，当前阶段不执行真实系统调用。
func (m *RouteManager) Apply(_ context.Context, dev TUNDevice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", types.ErrInvalidConfig)
	}
	m.keepaliveRoutes = append([]string(nil), m.plan.EndpointRoutes...)
	m.defaultRoutes = resolveDefaultRoutes(m.plan.Mode)
	m.defaultInjected = len(m.defaultRoutes) > 0
	m.boundDevice = dev.Name()
	m.applied = true
	return nil
}

// 清空已应用标记，便于上层复用同一计划对象。
func (m *RouteManager) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keepaliveRoutes = nil
	m.defaultRoutes = nil
	m.defaultInjected = false
	m.boundDevice = ""
	m.applied = false
	return nil
}

// 返回当前计划与应用状态的只读快照。
func (m *RouteManager) Snapshot() RouteSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	plan := m.plan.Clone()
	return RouteSnapshot{
		Mode:                 plan.Mode,
		DeviceName:           plan.DeviceName,
		MTU:                  plan.MTU,
		LocalPrefixes:        plan.LocalPrefixes,
		Routes:               plan.Routes,
		EndpointRoutes:       plan.EndpointRoutes,
		KeepaliveRoutes:      append([]string(nil), m.keepaliveRoutes...),
		DefaultRoutes:        append([]string(nil), m.defaultRoutes...),
		DefaultRouteInjected: m.defaultInjected,
		BoundDevice:          m.boundDevice,
		Applied:              m.applied,
	}
}

// 返回当前最小骨架需要记录的默认路由集合。
func resolveDefaultRoutes(mode RouteMode) []string {
	if mode != RouteModeGlobal {
		return nil
	}
	return []string{"0.0.0.0/0", "::/0"}
}
