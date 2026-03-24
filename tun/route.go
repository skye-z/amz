package tun

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/skye-z/amz/types"
)

type RouteMode string

const (
	RouteModeGlobal RouteMode = "global"
	RouteModeSplit  RouteMode = "split"
)

func (m RouteMode) String() string { return string(m) }

func (m RouteMode) Valid() bool {
	switch m {
	case RouteModeGlobal, RouteModeSplit:
		return true
	default:
		return false
	}
}

type RoutePlan struct {
	Mode           RouteMode
	DeviceName     string
	MTU            int
	LocalPrefixes  []string
	Routes         []string
	EndpointRoutes []string
}

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

type TUNDevice = Device

type RouteManager struct {
	mu              sync.Mutex
	plan            RoutePlan
	keepaliveRoutes []string
	defaultRoutes   []string
	defaultInjected bool
	boundDevice     string
	applied         bool
}

func NewRouteManager(plan RoutePlan) (*RouteManager, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return &RouteManager{plan: plan.Clone()}, nil
}

func (m *RouteManager) Apply(_ context.Context, dev Device) error {
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

func resolveDefaultRoutes(mode RouteMode) []string {
	if mode != RouteModeGlobal {
		return nil
	}
	return []string{"0.0.0.0/0", "::/0"}
}
