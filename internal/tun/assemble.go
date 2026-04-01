package tun

import (
	"context"
	"fmt"
	"runtime"

	"github.com/skye-z/amz/internal/testkit"
)

// ?????????????????????????????
type AssembleOptions struct {
	Platform string
	Device   DeviceConfig
	Config   Config
	Routes   RoutePlan
	Provider PlatformProvider
	Adapter  Adapter
}

// ???????????????????????????
func (o AssembleOptions) Validate() error {
	if err := o.Device.Validate(); err != nil {
		return err
	}
	if o.Config.Device.Name == "" && o.Config.Device.MTU == 0 {
		return nil
	}
	if err := o.Config.Validate(); err != nil {
		return err
	}
	return nil
}

// ??? provider??evice ??adapter ?????????????
type Assembly struct {
	Platform string
	Provider PlatformProvider
	Device   Device
	Adapter  Adapter
}

type deviceStarter interface {
	StartDevice() error
}

// ???????????????????????????????????
func (a *Assembly) PlaceholderError() error {
	if a == nil {
		return &PlaceholderError{
			Platform:  runtime.GOOS,
			Component: "assembly",
		}
	}
	if a.Provider != nil {
		if err := a.Provider.PlaceholderError(); err != nil {
			return err
		}
	}
	if a.Adapter != nil {
		if err := a.Adapter.PlaceholderError(); err != nil {
			return err
		}
	}
	return nil
}

// ?????????????????? provider??
func (a *Assembly) Close() error {
	if a == nil {
		return nil
	}
	if a.Provider == nil {
		return nil
	}
	return a.Provider.Close()
}

// ????????sing-tun ??????????????????????????????????
func Assemble(opts AssembleOptions) (*Assembly, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	platform := assemblePlatform(opts)
	provider, err := ensurePlatformProvider(platform, opts.Provider)
	if err != nil {
		return nil, err
	}
	device, err := provider.Open(context.Background(), opts.Device)
	if err != nil {
		return nil, err
	}

	adapter := assembleAdapter(opts)
	config := normalizeAssembleConfig(opts)
	if err := applyAssembleConfig(provider, adapter, device, config); err != nil {
		return nil, err
	}
	if err := applyAssembleRoutes(provider, adapter, device, opts.Routes); err != nil {
		return nil, err
	}
	if err := startAssembledDevice(provider, device); err != nil {
		return nil, err
	}

	return &Assembly{
		Platform: PlatformName(platform),
		Provider: provider,
		Device:   device,
		Adapter:  adapter,
	}, nil
}

func assemblePlatform(opts AssembleOptions) string {
	if opts.Platform != "" {
		return opts.Platform
	}
	return runtime.GOOS
}

func ensurePlatformProvider(platform string, provider PlatformProvider) (PlatformProvider, error) {
	if provider != nil {
		return provider, nil
	}
	return NewProviderForOS(platform)
}

func assembleAdapter(opts AssembleOptions) Adapter {
	if opts.Adapter != nil {
		return opts.Adapter
	}
	return NewSystemAdapter()
}

func normalizeAssembleConfig(opts AssembleOptions) Config {
	config := opts.Config
	if config.Device.Name == "" && config.Device.MTU == 0 {
		config = Config{Device: opts.Device}
	}
	if len(config.Addresses) == 0 {
		config.Addresses = []Address{{CIDR: testkit.TunIPv4CIDR}}
	}
	return config
}

func applyAssembleConfig(provider PlatformProvider, adapter Adapter, device Device, config Config) error {
	if err := adapter.ApplyConfig(context.Background(), device, config); err != nil {
		_ = provider.Close()
		return fmt.Errorf("apply placeholder tun config: %w", err)
	}
	return nil
}

func applyAssembleRoutes(provider PlatformProvider, adapter Adapter, device Device, routes RoutePlan) error {
	if !routes.Mode.Valid() && len(routes.Routes) == 0 && len(routes.EndpointRoutes) == 0 {
		return nil
	}
	if err := adapter.ApplyRoutes(context.Background(), device, routes); err != nil {
		_ = provider.Close()
		return fmt.Errorf("apply placeholder tun routes: %w", err)
	}
	return nil
}

func startAssembledDevice(provider PlatformProvider, device Device) error {
	startable, ok := device.(deviceStarter)
	if !ok {
		return nil
	}
	if err := startable.StartDevice(); err != nil {
		_ = provider.Close()
		return err
	}
	return nil
}
