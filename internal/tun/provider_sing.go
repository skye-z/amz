package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"

	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

type nativeTunFactory func(singtun.Options) (singtun.Tun, error)

const errUpdateSingTUNRouteOptions = "update sing-tun route options: %w"

type singProvider struct {
	platform          string
	factory           nativeTunFactory
	newNetworkMonitor func() (singtun.NetworkUpdateMonitor, error)
	newDefaultMonitor func(singtun.NetworkUpdateMonitor) (singtun.DefaultInterfaceMonitor, error)

	mu      sync.Mutex
	devices []Device
}

func newSingProvider(platform string) PlatformProvider {
	return &singProvider{
		platform: platform,
		factory: func(options singtun.Options) (singtun.Tun, error) {
			return singtun.New(options)
		},
		newNetworkMonitor: func() (singtun.NetworkUpdateMonitor, error) {
			return singtun.NewNetworkUpdateMonitor(logger.NOP())
		},
		newDefaultMonitor: func(networkMonitor singtun.NetworkUpdateMonitor) (singtun.DefaultInterfaceMonitor, error) {
			return singtun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), singtun.DefaultInterfaceMonitorOptions{
				InterfaceFinder: control.NewDefaultInterfaceFinder(),
			})
		},
	}
}

func (p *singProvider) Platform() string {
	return p.platform
}

func (p *singProvider) IsFake() bool {
	return false
}

func (p *singProvider) PlaceholderError() error {
	return nil
}

func (p *singProvider) Open(ctx context.Context, cfg DeviceConfig) (Device, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}

	device := &singDevice{
		creator: p.factory,
		name:    cfg.Name,
		mtu:     cfg.MTU,
		options: singtun.Options{
			Name:             cfg.Name,
			MTU:              uint32(cfg.MTU),
			AutoRoute:        false,
			InterfaceMonitor: noOpDefaultInterfaceMonitor{},
		},
	}
	if strings.EqualFold(p.platform, "windows") && p.newNetworkMonitor != nil && p.newDefaultMonitor != nil {
		networkMonitor, err := p.newNetworkMonitor()
		if err != nil {
			return nil, err
		}
		interfaceMonitor, err := p.newDefaultMonitor(networkMonitor)
		if err != nil {
			_ = networkMonitor.Close()
			return nil, err
		}
		device.networkMonitor = networkMonitor
		device.interfaceMonitor = interfaceMonitor
		device.options.InterfaceMonitor = interfaceMonitor
	}

	p.mu.Lock()
	p.devices = append(p.devices, device)
	p.mu.Unlock()
	return device, nil
}

func (p *singProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var closeErr error
	for _, device := range p.devices {
		if device == nil {
			continue
		}
		if err := device.Close(); err != nil && closeErr == nil && err != io.ErrClosedPipe {
			closeErr = err
		}
	}
	p.devices = nil
	return closeErr
}

type systemConfigurableDevice interface {
	Device
	ApplyTUNConfig(Config) error
}

type systemRouteConfigurableDevice interface {
	Device
	ApplyTUNRoutes(RoutePlan) error
	ResetTUNRoutes() error
}

type singDevice struct {
	creator          nativeTunFactory
	tun              singtun.Tun
	name             string
	mtu              int
	options          singtun.Options
	started          bool
	networkMonitor   singtun.NetworkUpdateMonitor
	interfaceMonitor singtun.DefaultInterfaceMonitor
}

func (d *singDevice) Name() string {
	return d.name
}

func (d *singDevice) MTU() int {
	return d.mtu
}

func (d *singDevice) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if d.tun == nil {
		return 0, io.ErrClosedPipe
	}
	return d.tun.Read(dst)
}

func (d *singDevice) WritePacket(ctx context.Context, packet []byte) (int, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if d.tun == nil {
		return 0, io.ErrClosedPipe
	}
	return d.tun.Write(packet)
}

func (d *singDevice) Close() error {
	if d.interfaceMonitor != nil {
		_ = d.interfaceMonitor.Close()
	}
	if d.networkMonitor != nil {
		_ = d.networkMonitor.Close()
	}
	if d.tun == nil {
		return nil
	}
	return d.tun.Close()
}

func (d *singDevice) StartDevice() error {
	if d.started {
		return nil
	}
	if d.creator != nil {
		if d.networkMonitor != nil {
			if err := d.networkMonitor.Start(); err != nil {
				return fmt.Errorf("start network monitor: %w", err)
			}
		}
		monitor := d.interfaceMonitor
		if monitor == nil {
			monitor = d.options.InterfaceMonitor
		}
		if monitor != nil {
			if err := monitor.Start(); err != nil {
				return fmt.Errorf("start interface monitor: %w", err)
			}
		}
		nativeTun, err := d.creator(d.options)
		if err != nil {
			return fmt.Errorf("open sing-tun device: %w", err)
		}
		d.tun = nativeTun
		if deviceName, err := nativeTun.Name(); err == nil && strings.TrimSpace(deviceName) != "" {
			d.name = deviceName
		}
	}
	if d.tun == nil {
		return fmt.Errorf("open sing-tun device: %w", io.ErrClosedPipe)
	}
	if starter, ok := any(d.tun).(interface{ Start() error }); ok {
		if err := starter.Start(); err != nil {
			return fmt.Errorf("start sing-tun device: %w", err)
		}
	}
	d.started = true
	return nil
}

func (d *singDevice) ApplyTUNConfig(cfg Config) error {
	options := d.options
	options.Name = cfg.Device.Name
	options.MTU = uint32(cfg.Device.MTU)
	options.Inet4Address = nil
	options.Inet6Address = nil
	for _, address := range cfg.Addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(address.CIDR))
		if err != nil {
			return fmt.Errorf("parse tun address %q: %w", address.CIDR, err)
		}
		if prefix.Addr().Is4() {
			options.Inet4Address = append(options.Inet4Address, prefix)
		} else if prefix.Addr().Is6() {
			options.Inet6Address = append(options.Inet6Address, prefix)
		}
	}
	if d.started {
		if err := d.tun.UpdateRouteOptions(options); err != nil {
			return fmt.Errorf(errUpdateSingTUNRouteOptions, err)
		}
	}
	d.options = options
	d.name = cfg.Device.Name
	d.mtu = cfg.Device.MTU
	return nil
}

func (d *singDevice) ApplyTUNRoutes(plan RoutePlan) error {
	previous := d.options
	next := previous
	next.AutoRoute = plan.Mode == RouteModeGlobal
	next.Inet4RouteAddress = nil
	next.Inet6RouteAddress = nil
	next.Inet4RouteExcludeAddress = nil
	next.Inet6RouteExcludeAddress = nil

	for _, route := range plan.Routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return fmt.Errorf("parse tun route %q: %w", route, err)
		}
		if prefix.Addr().Is4() {
			next.Inet4RouteAddress = append(next.Inet4RouteAddress, prefix)
		} else if prefix.Addr().Is6() {
			next.Inet6RouteAddress = append(next.Inet6RouteAddress, prefix)
		}
	}
	for _, route := range plan.EndpointRoutes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return fmt.Errorf("parse tun endpoint route %q: %w", route, err)
		}
		if prefix.Addr().Is4() {
			next.Inet4RouteExcludeAddress = append(next.Inet4RouteExcludeAddress, prefix)
		} else if prefix.Addr().Is6() {
			next.Inet6RouteExcludeAddress = append(next.Inet6RouteExcludeAddress, prefix)
		}
	}

	if d.started {
		if err := d.tun.UpdateRouteOptions(next); err != nil {
			rollbackErr := d.tun.UpdateRouteOptions(previous)
			if rollbackErr != nil {
				return errors.Join(
					fmt.Errorf(errUpdateSingTUNRouteOptions, err),
					fmt.Errorf("rollback sing-tun route options: %w", rollbackErr),
				)
			}
			return fmt.Errorf(errUpdateSingTUNRouteOptions, err)
		}
	}
	d.options = next
	return nil
}

func (d *singDevice) ResetTUNRoutes() error {
	next := d.options
	next.AutoRoute = false
	next.Inet4RouteAddress = nil
	next.Inet6RouteAddress = nil
	next.Inet4RouteExcludeAddress = nil
	next.Inet6RouteExcludeAddress = nil
	if d.started {
		if err := d.tun.UpdateRouteOptions(next); err != nil {
			return fmt.Errorf("reset sing-tun route options: %w", err)
		}
	}
	d.options = next
	return nil
}

type noOpDefaultInterfaceMonitor struct{}

func (noOpDefaultInterfaceMonitor) Start() error { return nil }
func (noOpDefaultInterfaceMonitor) Close() error { return nil }
func (noOpDefaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return nil
}
func (noOpDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (noOpDefaultInterfaceMonitor) AndroidVPNEnabled() bool  { return false }
func (noOpDefaultInterfaceMonitor) RegisterCallback(func(*control.Interface, int)) *list.Element[func(*control.Interface, int)] {
	return nil
}
func (noOpDefaultInterfaceMonitor) UnregisterCallback(*list.Element[func(*control.Interface, int)]) {
	// No-op: the default monitor does not track callbacks.
}
func (noOpDefaultInterfaceMonitor) RegisterMyInterface(string) {
	// No-op: the default monitor does not track interface names.
}
func (noOpDefaultInterfaceMonitor) MyInterface() string { return "" }
