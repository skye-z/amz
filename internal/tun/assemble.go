package tun

import (
	"context"
	"fmt"
	"runtime"
)

// 描述占位装配入口所需的最小输入参数。
type AssembleOptions struct {
	Platform string
	Device   DeviceConfig
	Config   Config
	Routes   RoutePlan
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
	Device   *FakeDevice
	Adapter  *FakeAdapter
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

	provider, err := NewProviderForOS(platform)
	if err != nil {
		return nil, err
	}
	device, err := provider.Open(context.Background(), opts.Device)
	if err != nil {
		return nil, err
	}

	adapter := NewFakeAdapter()
	config := opts.Config
	if config.Device.Name == "" && config.Device.MTU == 0 {
		config = Config{Device: opts.Device}
	}
	if len(config.Addresses) == 0 {
		config.Addresses = []Address{{CIDR: "172.16.0.2/32"}}
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

	return &Assembly{
		Platform: PlatformName(platform),
		Provider: provider,
		Device:   device,
		Adapter:  adapter,
	}, nil
}
