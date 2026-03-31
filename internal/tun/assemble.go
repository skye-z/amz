package tun

import (
	"context"
	"fmt"
	"runtime"

	"github.com/skye-z/amz/internal/testkit"
)

// 描述占位装配入口所需的最小输入参数。
type AssembleOptions struct {
	Platform string
	Device   DeviceConfig
	Config   Config
	Routes   RoutePlan
	Provider PlatformProvider
	Adapter  Adapter
}

// 检查装配参数是否具备最小设备信息。
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

// 描述 provider、device 与 adapter 的占位装配结果。
type Assembly struct {
	Platform string
	Provider PlatformProvider
	Device   Device
	Adapter  Adapter
}

type startableDevice interface {
	StartDevice() error
}

// 返回当前装配结果仍仅包含占位实现的结构化错误。
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

// 关闭装配结果持有的设备与 provider。
func (a *Assembly) Close() error {
	if a == nil {
		return nil
	}
	if a.Provider == nil {
		return nil
	}
	return a.Provider.Close()
}

// 返回更接近 sing-tun 装配流程的占位入口，但不会触发真实系统调用。
func Assemble(opts AssembleOptions) (*Assembly, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	platform := opts.Platform
	if platform == "" {
		platform = runtime.GOOS
	}

	provider := opts.Provider
	if provider == nil {
		var err error
		provider, err = NewProviderForOS(platform)
		if err != nil {
			return nil, err
		}
	}
	device, err := provider.Open(context.Background(), opts.Device)
	if err != nil {
		return nil, err
	}

	adapter := opts.Adapter
	if adapter == nil {
		adapter = NewSystemAdapter()
	}
	config := opts.Config
	if config.Device.Name == "" && config.Device.MTU == 0 {
		config = Config{Device: opts.Device}
	}
	if len(config.Addresses) == 0 {
		config.Addresses = []Address{{CIDR: testkit.TunIPv4CIDR}}
	}
	if err := adapter.ApplyConfig(context.Background(), device, config); err != nil {
		_ = provider.Close()
		return nil, fmt.Errorf("apply placeholder tun config: %w", err)
	}

	if opts.Routes.Mode.Valid() || len(opts.Routes.Routes) > 0 || len(opts.Routes.EndpointRoutes) > 0 {
		if err := adapter.ApplyRoutes(context.Background(), device, opts.Routes); err != nil {
			_ = provider.Close()
			return nil, fmt.Errorf("apply placeholder tun routes: %w", err)
		}
	}
	if startable, ok := device.(startableDevice); ok {
		if err := startable.StartDevice(); err != nil {
			_ = provider.Close()
			return nil, err
		}
	}

	return &Assembly{
		Platform: PlatformName(platform),
		Provider: provider,
		Device:   device,
		Adapter:  adapter,
	}, nil
}
