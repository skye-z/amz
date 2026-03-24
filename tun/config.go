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

type DeviceConfig struct {
	Name string
	MTU  int
}

type TUNDeviceConfig = DeviceConfig

func (c DeviceConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: tun name is required", types.ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", types.ErrInvalidConfig)
	}
	return nil
}

type Address struct {
	CIDR string
}

type TUNAddress = Address

func (a Address) Validate() error {
	cidr := strings.TrimSpace(a.CIDR)
	if cidr == "" {
		return fmt.Errorf("%w: address cidr is required", types.ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("%w: invalid address cidr: %v", types.ErrInvalidConfig, err)
	}
	return nil
}

type Configuration struct {
	Device    DeviceConfig
	Addresses []Address
}

type TUNConfiguration = Configuration

func (c Configuration) Clone() Configuration {
	clone := Configuration{
		Device:    c.Device,
		Addresses: make([]Address, len(c.Addresses)),
	}
	copy(clone.Addresses, c.Addresses)
	return clone
}

func (c Configuration) Validate() error {
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

type Device interface {
	Name() string
	MTU() int
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) (int, error)
	Close() error
}

type FakeDevice struct {
	mu      sync.Mutex
	name    string
	mtu     int
	inbound [][]byte
	written [][]byte
	closed  bool
}

type FakeTUNDevice = FakeDevice

func NewFakeDevice(cfg DeviceConfig) (*FakeDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &FakeDevice{name: cfg.Name, mtu: cfg.MTU}, nil
}

func NewFakeTUNDevice(cfg DeviceConfig) (*FakeDevice, error) {
	return NewFakeDevice(cfg)
}

func (d *FakeDevice) Name() string { return d.name }
func (d *FakeDevice) MTU() int     { return d.mtu }

func (d *FakeDevice) InjectInbound(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	buf := append([]byte(nil), packet...)
	d.inbound = append(d.inbound, buf)
	return nil
}

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

func (d *FakeDevice) WritePacket(_ context.Context, packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	buf := append([]byte(nil), packet...)
	d.written = append(d.written, buf)
	return len(packet), nil
}

func (d *FakeDevice) WrittenPackets() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, 0, len(d.written))
	for _, packet := range d.written {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

func (d *FakeDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

type ConfigSnapshot struct {
	Device      DeviceConfig
	Addresses   []Address
	BoundDevice string
	Applied     bool
}

type TUNConfigSnapshot = ConfigSnapshot

type ConfigManager struct {
	mu          sync.Mutex
	config      Configuration
	boundDevice string
	applied     bool
}

type TUNConfigManager = ConfigManager

func NewConfigManager(cfg Configuration) (*ConfigManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &ConfigManager{config: cfg.Clone()}, nil
}

func NewTUNConfigManager(cfg Configuration) (*ConfigManager, error) {
	return NewConfigManager(cfg)
}

func (m *ConfigManager) Apply(_ context.Context, dev Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dev == nil {
		return fmt.Errorf("%w: tun device is required", types.ErrInvalidConfig)
	}
	m.boundDevice = dev.Name()
	m.applied = true
	return nil
}

func (m *ConfigManager) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.boundDevice = ""
	m.applied = false
	return nil
}

func (m *ConfigManager) Snapshot() ConfigSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := m.config.Clone()
	return ConfigSnapshot{
		Device:      clone.Device,
		Addresses:   clone.Addresses,
		BoundDevice: m.boundDevice,
		Applied:     m.applied,
	}
}
