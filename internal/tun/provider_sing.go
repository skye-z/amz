package tun

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"

	singtun "github.com/sagernet/sing-tun"
)

type nativeTunFactory func(singtun.Options) (singtun.Tun, error)

type singProvider struct {
	platform string
	factory  nativeTunFactory

	mu      sync.Mutex
	devices []Device
}

func newSingProvider(platform string) PlatformProvider {
	return &singProvider{
		platform: platform,
		factory: func(options singtun.Options) (singtun.Tun, error) {
			return singtun.New(options)
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

	nativeTun, err := p.factory(singtun.Options{
		Name:      cfg.Name,
		MTU:       uint32(cfg.MTU),
		AutoRoute: false,
	})
	if err != nil {
		return nil, fmt.Errorf("open sing-tun device: %w", err)
	}
	if starter, ok := any(nativeTun).(interface{ Start() error }); ok {
		if err := starter.Start(); err != nil {
			_ = nativeTun.Close()
			return nil, fmt.Errorf("start sing-tun device: %w", err)
		}
	}

	deviceName, err := nativeTun.Name()
	if err != nil || strings.TrimSpace(deviceName) == "" {
		deviceName = cfg.Name
	}

	device := &singDevice{
		tun:  nativeTun,
		name: deviceName,
		mtu:  cfg.MTU,
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

type singDevice struct {
	tun  singtun.Tun
	name string
	mtu  int
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
	return d.tun.Read(dst)
}

func (d *singDevice) WritePacket(ctx context.Context, packet []byte) (int, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	return d.tun.Write(packet)
}

func (d *singDevice) Close() error {
	return d.tun.Close()
}

func (d *singDevice) ApplyTUNConfig(cfg Config) error {
	options := singtun.Options{
		Name:      cfg.Device.Name,
		MTU:       uint32(cfg.Device.MTU),
		AutoRoute: false,
	}
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
	if err := d.tun.UpdateRouteOptions(options); err != nil {
		return fmt.Errorf("update sing-tun route options: %w", err)
	}
	d.name = cfg.Device.Name
	d.mtu = cfg.Device.MTU
	return nil
}
